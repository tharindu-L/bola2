"""Serializes a GraphQLSelection tree plus argument bindings into an executable
GraphQL query/mutation string and a matching variables dict.
"""

from __future__ import annotations

from bola_framework.models import GraphQLSelection, Parameter


def build_query(
    operation_kind: str,
    root_field: str,
    root_selection: GraphQLSelection,
    argument_values: dict[str, object],
    max_depth: int = 4,
) -> tuple[str, dict]:
    """Build a query/mutation string for `root_field` using `root_selection`'s
    children as the selection set, binding `argument_values` (keyed by
    "<dotted.path>.<arg name>" as produced by the identifier detector, or
    simply by argument name for the root field) as GraphQL variables.
    """
    variables: dict[str, object] = {}
    var_declarations: list[str] = []

    root_args_str, root_selection_str = _render_field(
        root_selection,
        argument_values,
        variables,
        var_declarations,
        path_prefix="",
        depth=0,
        max_depth=max_depth,
        is_root=True,
    )

    var_decl_str = f"({', '.join(var_declarations)})" if var_declarations else ""
    query = (
        f"{operation_kind}{var_decl_str} {{\n"
        f"  {root_field}{root_args_str} {root_selection_str}\n"
        f"}}"
    )
    return query, variables


def _render_field(
    node: GraphQLSelection,
    argument_values: dict[str, object],
    variables: dict,
    var_declarations: list[str],
    path_prefix: str,
    depth: int,
    max_depth: int,
    is_root: bool = False,
) -> tuple[str, str]:
    current_path = f"{path_prefix}.{node.field_name}" if path_prefix else node.field_name

    args_parts = []
    for arg in node.arguments:
        var_name = _var_name_for(current_path, arg.name)
        lookup_keys = (f"{current_path}.{arg.name}", arg.name)
        value = next((argument_values[k] for k in lookup_keys if k in argument_values), None)
        if value is None:
            continue
        gql_type = _graphql_type_hint(arg)
        var_declarations.append(f"${var_name}: {gql_type}")
        variables[var_name] = value
        args_parts.append(f"{arg.name}: ${var_name}")

    args_str = f"({', '.join(args_parts)})" if args_parts else ""

    if not node.selections:
        # No children were discovered for this field, meaning the discoverer
        # treated it as a scalar (or a cycle/depth cutoff was hit before any
        # child could be expanded). Emit no selection set, which is correct
        # for genuine scalars; deeply-nested object types truncated by
        # max_selection_depth are a known, documented limitation.
        return args_str, ""

    child_strs = []
    for child in node.selections:
        child_args, child_sel = _render_field(
            child,
            argument_values,
            variables,
            var_declarations,
            current_path,
            depth + 1,
            max_depth,
        )
        alias = f"{child.alias}: " if child.alias else ""
        child_strs.append(f"{alias}{child.field_name}{child_args} {child_sel}".strip())

    selection_str = "{ " + " ".join(child_strs) + " }"
    return args_str, selection_str


def _var_name_for(path: str, arg_name: str) -> str:
    safe_path = path.replace(".", "_")
    return f"{safe_path}_{arg_name}"


_SCALAR_MAP = {
    "integer": "Int",
    "number": "Float",
    "string": "String",
    "boolean": "Boolean",
}


def _graphql_type_hint(arg: Parameter) -> str:
    if arg.type_hint and arg.type_hint[0].isupper():
        # Already looks like a GraphQL named type (ID, User, etc.)
        base = arg.type_hint
    else:
        base = _SCALAR_MAP.get((arg.type_hint or "").lower(), "String")
    return f"{base}!" if arg.required else base
