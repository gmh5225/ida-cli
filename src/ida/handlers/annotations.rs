//! Comment and rename handlers.

use crate::error::ToolError;
use crate::ida::handlers::resolve_address;
use idalib::IDB;
use serde_json::{json, Value};

pub fn handle_set_comments(
    idb: &Option<IDB>,
    addr: Option<u64>,
    name: Option<&str>,
    offset: u64,
    comment: &str,
    repeatable: bool,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let addr = resolve_address(idb, addr, name, offset)?;
    if repeatable {
        db.set_cmt_with(addr, comment, true)?;
    } else {
        db.set_cmt(addr, comment)?;
    }
    Ok(json!({
        "address": format!("{:#x}", addr),
        "repeatable": repeatable,
        "comment": comment,
    }))
}

pub fn handle_rename(
    idb: &Option<IDB>,
    addr: Option<u64>,
    current_name: Option<&str>,
    name: &str,
    flags: i32,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let addr = resolve_address(idb, addr, current_name, 0)?;
    if flags == 0 {
        db.set_name(addr, name)?;
    } else {
        db.set_name_with_flags(addr, name, flags)?;
    }
    Ok(json!({
        "address": format!("{:#x}", addr),
        "name": name,
        "flags": flags,
    }))
}

pub fn handle_rename_lvar(
    idb: &Option<IDB>,
    func_addr: u64,
    lvar_name: &str,
    new_name: &str,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    db.rename_lvar(func_addr, lvar_name, new_name)?;
    Ok(json!({
        "func_address": format!("{func_addr:#x}"),
        "lvar_name": lvar_name,
        "new_name": new_name,
    }))
}

pub fn handle_set_lvar_type(
    idb: &Option<IDB>,
    func_addr: u64,
    lvar_name: &str,
    type_str: &str,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    db.set_lvar_type(func_addr, lvar_name, type_str)?;
    Ok(json!({
        "func_address": format!("{func_addr:#x}"),
        "lvar_name": lvar_name,
        "type_str": type_str,
    }))
}

pub fn handle_set_decompiler_comment(
    idb: &Option<IDB>,
    func_addr: u64,
    addr: u64,
    itp: i32,
    comment: &str,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    db.set_decompiler_comment(func_addr, addr, itp, comment)?;
    Ok(json!({
        "func_address": format!("{func_addr:#x}"),
        "address": format!("{addr:#x}"),
        "itp": itp,
        "comment": comment,
    }))
}
