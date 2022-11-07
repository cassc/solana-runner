use {
    serde::{Deserialize, Serialize},
    serde_json::Result,
    solana_bpf_loader_program::{
        create_vm, serialization::serialize_parameters, syscalls::register_syscalls,
        ThisInstructionMeter,
    },
    solana_program_runtime::invoke_context::{prepare_mock_invoke_context, InvokeContext},
    solana_rbpf::{
        assembler::assemble,
        elf::Executable,
        static_analysis::Analysis,
        verifier::RequisiteVerifier,
        vm::{Config, VerifiedExecutable},
    },
    solana_sdk::{
        account::AccountSharedData, bpf_loader, instruction::AccountMeta, pubkey::Pubkey,
        sysvar::rent::Rent, transaction_context::TransactionContext,
    },
    std::{
        fmt::{Debug, Formatter},
        fs::File,
        io::{Read, Seek, SeekFrom},
        path::Path,
        time::{Duration, Instant},
    },
};

#[derive(Serialize, Deserialize, Debug)]
struct Account {
    key: Pubkey,
    owner: Pubkey,
    is_signer: bool,
    is_writable: bool,
    lamports: u64,
    data: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
struct Input {
    accounts: Vec<Account>,
    instruction_data: Vec<u8>,
}
fn load_accounts(path: &Path) -> Result<Input> {
    let file = File::open(path).unwrap();
    let input: Input = serde_json::from_reader(file)?;
    eprintln!("Program input:");
    eprintln!("accounts {:?}", &input.accounts);
    eprintln!("instruction_data {:?}", &input.instruction_data);
    eprintln!("----------------------------------------");
    Ok(input)
}

fn main() {
    let loader_id = bpf_loader::id();
    let mut transaction_accounts = vec![
        (
            loader_id,
            AccountSharedData::new(0, 0, &solana_sdk::native_loader::id()),
        ),
        (
            Pubkey::new_unique(),
            AccountSharedData::new(0, 0, &loader_id),
        ),
    ];
    let mut instruction_accounts = Vec::new();
    let instruction_data = {
        let pubkey = Pubkey::new_unique();
        transaction_accounts.push((pubkey, AccountSharedData::new(0, 0, &Pubkey::new_unique())));
        instruction_accounts.push(AccountMeta {
            pubkey,
            is_signer: false,
            is_writable: true,
        });
        vec![]
    };

    let program_indices = [0, 1];
    let preparation =
        prepare_mock_invoke_context(transaction_accounts, instruction_accounts, &program_indices);
    let mut transaction_context = TransactionContext::new(
        preparation.transaction_accounts,
        Some(Rent::default()),
        1,
        1,
    );
    let mut invoke_context = InvokeContext::new_mock(&mut transaction_context, &[]);
    invoke_context
        .transaction_context
        .get_next_instruction_context()
        .unwrap()
        .configure(
            &program_indices,
            &preparation.instruction_accounts,
            &instruction_data,
        );
    invoke_context.push().unwrap();
    let (_parameter_bytes, regions, account_lengths) = serialize_parameters(
        invoke_context.transaction_context,
        invoke_context
            .transaction_context
            .get_current_instruction_context()
            .unwrap(),
        true, // should_cap_ix_accounts
    )
    .unwrap();
    let compute_meter = invoke_context.get_compute_meter();
    let mut instruction_meter = ThisInstructionMeter { compute_meter };

    let program = "/home/garfield/projects/solana-projects/quikstart/solana_hello_world/target/deploy/hello_world.so";
    let mut file = File::open(&Path::new(program)).unwrap();
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).unwrap();
    let syscall_registry = register_syscalls(&invoke_context.feature_set, true).unwrap();
    let config = Config::default();
    let executable = if magic == [0x7f, 0x45, 0x4c, 0x46] {
        Executable::<ThisInstructionMeter>::from_elf(&contents, config, syscall_registry)
            .map_err(|err| format!("Executable constructor failed: {:?}", err))
    } else {
        assemble::<ThisInstructionMeter>(
            std::str::from_utf8(contents.as_slice()).unwrap(),
            config,
            syscall_registry,
        )
    }
    .unwrap();

    let mut verified_executable =
        VerifiedExecutable::<RequisiteVerifier, ThisInstructionMeter>::from_executable(executable)
            .map_err(|err| format!("Executable verifier failed: {:?}", err))
            .unwrap();

    verified_executable.jit_compile().unwrap();
    let mut analysis = LazyAnalysis::new(verified_executable.get_executable());

    let mut vm = create_vm(
        &verified_executable,
        regions,
        account_lengths,
        &mut invoke_context,
    )
    .unwrap();
    let start_time = Instant::now();
    let result = { vm.execute_program_jit(&mut instruction_meter) };
    let duration = Instant::now() - start_time;

    eprintln!("Trace is saved in trace.out");
    let mut file = File::create("trace.out").unwrap();
    vm.get_program_environment()
        .tracer
        .write(&mut file, analysis.analyze())
        .unwrap();

    let instruction_count = vm.get_total_instruction_count();
    drop(vm);

    let output = Output {
        result: format!("{:?}", result),
        instruction_count,
        execution_time: duration,
        log: invoke_context
            .get_log_collector()
            .unwrap()
            .borrow()
            .get_recorded_content()
            .to_vec(),
    };

    println!("Program output:");
    println!("{:?}", output);
}

#[derive(Serialize)]
struct Output {
    result: String,
    instruction_count: u64,
    execution_time: Duration,
    log: Vec<String>,
}

impl Debug for Output {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Result: {}", self.result)?;
        writeln!(f, "Instruction Count: {}", self.instruction_count)?;
        writeln!(f, "Execution time: {} us", self.execution_time.as_micros())?;
        for line in &self.log {
            writeln!(f, "{}", line)?;
        }
        Ok(())
    }
}

// Replace with std::lazy::Lazy when stabilized.
// https://github.com/rust-lang/rust/issues/74465
struct LazyAnalysis<'a> {
    analysis: Option<Analysis<'a, ThisInstructionMeter>>,
    executable: &'a Executable<ThisInstructionMeter>,
}

impl<'a> LazyAnalysis<'a> {
    fn new(executable: &'a Executable<ThisInstructionMeter>) -> Self {
        Self {
            analysis: None,
            executable,
        }
    }

    fn analyze(&mut self) -> &Analysis<ThisInstructionMeter> {
        if let Some(ref analysis) = self.analysis {
            return analysis;
        }
        self.analysis
            .insert(Analysis::from_executable(self.executable).unwrap())
    }
}
