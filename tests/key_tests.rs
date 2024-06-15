extern crate bw_key;

use std::io::Write;
use std::process::Command;
use bw_key::ossh_privkey::parse_keystr;
use bw_key::proto::{Identity, Message, to_bytes};
use bw_key::sshsock::SshSock;

fn verify_key_added(comment: &str) -> bool {
    let output = Command::new("ssh-add")
        .arg("-l")
        .output()
        .expect("Failed to execute ssh-add command");

    println!("ssh-add -l output: {}", String::from_utf8_lossy(&output.stdout));
    
    if !output.status.success() {
        println!("ssh-add command failed with status: {}", output.status);
        return false;
    }

    let contains = String::from_utf8_lossy(&output.stdout).contains(comment);
    println!("Key with comment '{}' found: {}", comment, contains);
    contains
}

fn test_key(ssh_key: &str, passphrase: Option<&str>, comment: &str) {
    println!("\nTesting key with comment: {}", comment);
    
    let key = match parse_keystr(ssh_key.as_bytes(), passphrase) {
        Ok(k) => {
            println!("Successfully parsed key");
            k
        },
        Err(e) => {
            println!("Failed to parse key: {:?}", e);
            panic!("Key parsing failed");
        }
    };

    let mut client = match SshSock::new() {
        Ok(c) => {
            println!("Successfully created SSH socket");
            c
        },
        Err(e) => {
            println!("Failed to create SSH socket: {:?}", e);
            panic!("SSH socket creation failed");
        }
    };

    let identity = Identity {
        private_key: key,
        comment: comment.to_string(),
    };

    let req = Message::AddIdentity(identity);
    let req_bytes = to_bytes(&to_bytes(&req).unwrap()).unwrap();
    
    match client.write(req_bytes.as_slice()) {
        Ok(_) => println!("Successfully wrote key to SSH agent"),
        Err(e) => {
            println!("Failed to write key to SSH agent: {:?}", e);
            panic!("Failed to write key to SSH agent");
        }
    }

    // 等待一小段时间确保密钥已被添加
    std::thread::sleep(std::time::Duration::from_millis(500));

    // 验证密钥是否成功添加
    assert!(verify_key_added(comment), "Failed to verify key addition with comment: {}", comment);
}

// 测试未加密的密钥
#[test]
fn test_unencrypted_ed25519() {
    let ssh_key = include_str!("assets/unencrypt/openssh/test_ed25519");
    test_key(ssh_key, None, "ed25519-unencrypt");
}

#[test]
fn test_unencrypted_rsa() {
    let ssh_key = include_str!("assets/unencrypt/openssh/test_rsa");
    test_key(ssh_key, None, "rsa-unencrypt");
}

// 测试加密的密钥
#[test]
fn test_encrypted_rsa() {
    let ssh_key = include_str!("assets/encrypt/PEM/test_rsa");
    test_key(ssh_key, Some("11111111"), "rsa-encrypt");
}

#[test]
fn test_encrypted_ecdsa() {
    let ssh_key = include_str!("assets/encrypt/PEM/test_ecdsa");
    test_key(ssh_key, Some("11111111"), "ecdsa-encrypt");
}

// 清理函数：在所有测试完成后删除添加的密钥
#[test]
fn cleanup_keys() {
    Command::new("ssh-add")
        .arg("-D")
        .status()
        .expect("Failed to clean up keys");
}
