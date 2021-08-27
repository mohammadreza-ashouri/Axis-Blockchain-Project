// Axis AXISVM core module 
// Axis Labs 2021
// Writtem by Mohammadreza Ashouri and Florian Ahr  // ashourics@gmail.com 
// AXIS VM supports the EVM opcodes




use util::not_implement_panic;
use super::util;
use super::state;
extern crate ethereum_types;
use ethereum_types::{H160, U256};



// Environment specifications 
pub struct Environment {
 
    gas_cost: usize, // gas
    value: usize,     
    code: Vec<u8>,    
    input: Vec<u8>,  
    code_supervisor: H160, 
    sender: H160,     
  
}

impl Environment {
    pub fn new(code_supervisor: H160, sender: H160, gas_cost: usize, value: usize) -> Self {
        return Self {
            code_supervisor,
            sender,
            gas_cost,
            value,
            code: Default::default(),
            input: Default::default(),
        };
    }


    pub fn set_code(&mut self, code: Vec<u8>) {
        self.code = code;
    }

    pub fn set_input(&mut self, input: Vec<u8>) {
        self.input = input;
    }




  
}

pub struct AXISVM {
    env: Environment, 
    pc: usize,        // AXIS VM Program Counter
    gas: usize,       // gas
    sp: usize,        
    asm: Vec<String>, // Store the executed instruction Used for disassembly
    stack: Vec<U256>, // Temporary stack area retained for the life cycle of a transaction
    memory: Vec<u8>,  // Temporary memory area retained during the life cycle of a transaction
    returns: Vec<u8>, // Action return value
}

/// Opcode
impl AXISVM {
    pub fn new(env: Environment) -> Self {
        let gas = env.value / env.gas_cost;

        Self {
            env,
            pc: 0,
            gas,
            sp: 0,
            stack: Default::default(),
            memory: Default::default(),
            asm: Default::default(),
            returns: Default::default(),
        }
    }

    /// push to the AXIS stack
    fn push(&mut self, value: U256) {
        self.stack.push(value);
        self.sp += 1;
    }

    /// pop from the AXIS stack
    fn pop(&mut self) -> U256 {
        let value = self.stack.pop().unwrap();
        self.sp -= 1;
        return value;
    }

    /// code execution
    fn exec(&mut self, contract: &mut state::AccountState) -> bool {
        let opcode = self.env.code[self.pc];
        self.pc += 1;

        // opcodes -- supporting the EVM opcs updatable based on new EVM opcodes and other virtual machines such as Tron
        match opcode {
            // 0x00
            0x00 => self.op_stop(),
            0x01 => self.op_add(),
            0x02 => self.op_mul(),
            0x03 => self.op_sub(),
            0x04 => self.op_div(),
            0x05 => self.op_sdiv(),
            0x06 => self.op_mod(),
            0x07 => self.op_smod(),
            0x08 => self.op_addmod(),
            0x09 => self.op_mulmod(),
            0x0a => self.op_exp(),
            0x0b => self.op_sig_next_end(),
            // 0x10
            0x10 => self.op_lt(),
            0x11 => self.op_gt(),
            0x12 => self.op_slt(),
            0x13 => self.op_sgt(),
            0x14 => self.op_eq(),
            0x15 => self.op_is_zero(),
            0x16 => self.op_and(),
            0x17 => self.op_or(),
            0x18 => self.op_xor(),
            0x19 => self.op_not(),
            0x1a => self.op_byte(),
            // 0x20
            0x20 => self.op_sha3(),
            // 0x30
            0x30 => self.op_address(),
            0x31 => self.op_balance(),
            0x32 => self.op_origin(),
            0x33 => self.op_caller(),
            0x34 => self.op_callvalue(),
            0x35 => self.op_calldataload(),
            0x36 => self.op_calldatasize(),
            0x37 => self.op_calldatacopy(),
            0x38 => self.op_codesize(),
            0x39 => self.op_codecopy(),
            0x3a => self.op_gasprice(),
            0x3b => self.op_extcodesize(),
            0x3c => self.op_extcodecopy(),
            0x3d => self.op_returndatasize(),
            0x3e => self.op_returndatacopy(),
            0x3f => self.op_extcodehash(),
            // 0x40
            0x40 => self.op_blockhash(),
            0x41 => self.op_coinbase(),
            0x42 => self.op_timestamp(),
            0x43 => self.op_number(),
            0x44 => self.op_difficulty(),
            0x45 => self.op_gaslimit(),
            // 0x50
            0x50 => self.op_pop(),
            0x51 => self.op_mload(),
            0x52 => self.op_mstore(),
            0x54 => self.op_sload(contract),
            0x55 => self.op_sstore(contract),
            0x56 => self.op_jump(),
            0x57 => self.op_jumpi(),
            0x58 => self.op_pc(),
            0x59 => self.op_msize(),
            0x5a => self.op_gas(),
            0x5b => self.op_jumpdest(),
            // 0x60, 0x70
            0x60 => self.op_push(1),
            0x61 => self.op_push(2),
            0x62 => self.op_push(3),
            0x63 => self.op_push(4),
            0x64 => self.op_push(5),
            0x65 => self.op_push(6),
            0x66 => self.op_push(7),
            0x67 => self.op_push(8),
            0x68 => self.op_push(9),
            0x69 => self.op_push(10),
            0x6a => self.op_push(11),
            0x6b => self.op_push(12),
            0x6c => self.op_push(13),
            0x6d => self.op_push(14),
            0x6e => self.op_push(15),
            0x6f => self.op_push(16),
            0x70 => self.op_push(17),
            0x71 => self.op_push(18),
            0x72 => self.op_push(19),
            0x73 => self.op_push(20),
            0x74 => self.op_push(21),
            0x75 => self.op_push(22),
            0x76 => self.op_push(23),
            0x77 => self.op_push(24),
            0x78 => self.op_push(25),
            0x79 => self.op_push(26),
            0x7a => self.op_push(27),
            0x7b => self.op_push(28),
            0x7c => self.op_push(29),
            0x7d => self.op_push(30),
            0x7e => self.op_push(31),
            0x7f => self.op_push(32),
            // 0x80
            0x80 => self.op_dup(1),
            0x81 => self.op_dup(2),
            0x82 => self.op_dup(3),
            0x83 => self.op_dup(4),
            0x84 => self.op_dup(5),
            0x85 => self.op_dup(6),
            0x86 => self.op_dup(7),
            0x87 => self.op_dup(8),
            0x88 => self.op_dup(9),
            0x89 => self.op_dup(10),
            0x8a => self.op_dup(11),
            0x8b => self.op_dup(12),
            0x8c => self.op_dup(13),
            0x8d => self.op_dup(14),
            0x8e => self.op_dup(15),
            0x8f => self.op_dup(16),
            // 0x90
            0x90 => self.op_swap(1),
            0x91 => self.op_swap(2),
            0x92 => self.op_swap(3),
            0x93 => self.op_swap(4),
            0x94 => self.op_swap(5),
            0x95 => self.op_swap(6),
            0x96 => self.op_swap(7),
            0x97 => self.op_swap(8),
            0x98 => self.op_swap(9),
            0x99 => self.op_swap(10),
            0x9a => self.op_swap(11),
            0x9b => self.op_swap(12),
            0x9c => self.op_swap(13),
            0x9d => self.op_swap(14),
            0x9e => self.op_swap(15),
            0x9f => self.op_swap(16),
            // 0xa0
            0xa0 => self.op_log0(),
            0xa1 => self.op_log1(),
            0xa2 => self.op_log2(),
            0xa3 => self.op_log3(),
            0xa4 => self.op_log4(),
            // 0xf0
            0xf0 => self.op_create(),
            0xf1 => self.op_call(),
            0xf2 => self.op_callcode(),
            0xf3 => self.op_return(),
            0xf4 => self.op_delegatecall(),
            0xf5 => self.op_create2(),
            0xfa => self.op_staticcall(),
            0xfd => self.op_revert(),
            0xff => self.op_selfdestruct(),
            _ => not_implement_panic(),
        }



  /// Iterate exec until transaction ends
    pub fn transaction_execute(&mut self, contract: &mut state::AccountState) {
        loop {
            if self.pc >= self.env.code.len() {
                break;
            }

            if self.exec(contract) {
                break;
            }
        }
    }


      // Flag to end the transaction return only true
          return match opcode {
            0xf3 => true,
            _ => false,
        };
    }

    fn consume_gas(&mut self, gas: usize) {
        if self.gas >= gas {
            self.gas -= gas;
        } else {
            panic!("consume_gas: out of gas!");
        }
    }



    pub fn disassemble(code: &str) {
        let mut env = Environment::new(
            Default::default(),
            Default::default(),
            1_000_000_000,
            100_000_000_000_000_000,
        );


        fn push_assembly(&mut self, mnemonic: &str) {
            self.asm.push(mnemonic.to_string());
        }

        env.set_code(util::str_to_bytes(code));
        let mut axvm = AXISVM::new(env);
        let mut contract = state::AccountState::new(code.to_string());
        axvm.transaction_execute(&mut contract);

        for mnemonic in axvm.asm {
            println!("{}", mnemonic);
        }
    }


}