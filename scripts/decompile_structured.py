import ida_hexrays
import ida_name
import json


def serialize_expr(e, depth=0):
    if depth > MAX_DEPTH:
        return {"op": "...", "truncated": True}
    node = {"op": ida_hexrays.get_ctype_name(e.op)}
    if INCLUDE_ADDRESSES and e.ea != 0xFFFFFFFFFFFFFFFF and e.ea != 0:
        node["ea"] = hex(e.ea)
    if INCLUDE_TYPES:
        try:
            node["type"] = str(e.type)
        except Exception:
            pass
    op = e.op
    if op == ida_hexrays.cot_num:
        node["value"] = e.numval()
    elif op == ida_hexrays.cot_str:
        node["value"] = str(e.string)
    elif op == ida_hexrays.cot_obj:
        obj_ea = int(e.obj_ea)
        node["obj_ea"] = hex(obj_ea)
        name = ida_name.get_name(obj_ea)
        if name:
            node["name"] = name
    elif op == ida_hexrays.cot_var:
        node["var_idx"] = int(e.v.idx)
    elif op == ida_hexrays.cot_ref:
        node["x"] = serialize_expr(e.x, depth + 1)
    elif op == ida_hexrays.cot_ptr:
        node["x"] = serialize_expr(e.x, depth + 1)
    elif op == ida_hexrays.cot_call:
        node["target"] = serialize_expr(e.x, depth + 1)
        node["args"] = [serialize_expr(a, depth + 1) for a in e.a]
    elif op == ida_hexrays.cot_cast:
        node["x"] = serialize_expr(e.x, depth + 1)
        try:
            node["cast_type"] = str(e.type)
        except Exception:
            pass
    elif op == ida_hexrays.cot_memptr:
        node["x"] = serialize_expr(e.x, depth + 1)
        node["offset"] = int(e.m)
    elif op == ida_hexrays.cot_memref:
        node["x"] = serialize_expr(e.x, depth + 1)
        node["offset"] = int(e.m)
    elif op == ida_hexrays.cot_idx:
        node["x"] = serialize_expr(e.x, depth + 1)
        node["y"] = serialize_expr(e.y, depth + 1)
    elif op == ida_hexrays.cot_tern:
        node["cond"] = serialize_expr(e.x, depth + 1)
        node["then"] = serialize_expr(e.y, depth + 1)
        node["else"] = serialize_expr(e.z, depth + 1)
    elif e.x is not None:
        node["x"] = serialize_expr(e.x, depth + 1)
        if e.y is not None:
            node["y"] = serialize_expr(e.y, depth + 1)
        if e.z is not None:
            node["z"] = serialize_expr(e.z, depth + 1)
    return node


def serialize_stmt(s, depth=0):
    if depth > MAX_DEPTH:
        return {"op": "...", "truncated": True}
    node = {"op": ida_hexrays.get_ctype_name(s.op)}
    if INCLUDE_ADDRESSES and s.ea != 0xFFFFFFFFFFFFFFFF and s.ea != 0:
        node["ea"] = hex(s.ea)
    op = s.op
    if op == ida_hexrays.cit_block:
        node["stmts"] = [serialize_stmt(c, depth + 1) for c in s.cblock]
    elif op == ida_hexrays.cit_expr:
        node["expr"] = serialize_expr(s.cexpr, depth + 1)
    elif op == ida_hexrays.cit_if:
        node["cond"] = serialize_expr(s.cif.expr, depth + 1)
        node["then"] = serialize_stmt(s.cif.ithen, depth + 1)
        if s.cif.ielse is not None:
            node["else"] = serialize_stmt(s.cif.ielse, depth + 1)
    elif op == ida_hexrays.cit_for:
        node["init"] = serialize_expr(s.cfor.init, depth + 1)
        node["cond"] = serialize_expr(s.cfor.expr, depth + 1)
        node["step"] = serialize_expr(s.cfor.step, depth + 1)
        node["body"] = serialize_stmt(s.cfor.body, depth + 1)
    elif op == ida_hexrays.cit_while:
        node["cond"] = serialize_expr(s.cwhile.expr, depth + 1)
        node["body"] = serialize_stmt(s.cwhile.body, depth + 1)
    elif op == ida_hexrays.cit_do:
        node["body"] = serialize_stmt(s.cdo.body, depth + 1)
        node["cond"] = serialize_expr(s.cdo.expr, depth + 1)
    elif op == ida_hexrays.cit_return:
        if s.creturn.expr is not None:
            node["value"] = serialize_expr(s.creturn.expr, depth + 1)
    elif op == ida_hexrays.cit_switch:
        node["switch_expr"] = serialize_expr(s.cswitch.expr, depth + 1)
        cases = []
        for case in s.cswitch.cases:
            case_node = {
                "values": list(case.values),
                "body": serialize_stmt(case, depth + 1),
            }
            cases.append(case_node)
        node["cases"] = cases
    elif op == ida_hexrays.cit_goto:
        node["label"] = int(s.cgoto.label_num)
    return node


try:
    if not ida_hexrays.init_hexrays_plugin():
        print(json.dumps({"error": "Hex-Rays is not available"}))
    else:
        cfunc = ida_hexrays.decompile(EA)
        if cfunc is None:
            print(json.dumps({"error": f"Failed to decompile {hex(EA)}"}))
        else:
            lvars = []
            for i, lv in enumerate(cfunc.lvars):
                lvars.append(
                    {
                        "idx": i,
                        "name": str(lv.name),
                        "type": str(lv.type()),
                        "is_arg": bool(lv.is_arg_var),
                    }
                )
            result = {
                "function": ida_name.get_name(EA) or hex(EA),
                "address": hex(EA),
                "return_type": str(cfunc.type.get_rettype()),
                "num_args": int(cfunc.argidx.size() if hasattr(cfunc, "argidx") else 0),
                "lvars": lvars,
                "body": serialize_stmt(cfunc.body),
            }
            print(json.dumps(result))
except Exception as e:
    import traceback

    print(json.dumps({"error": str(e), "traceback": traceback.format_exc()}))
