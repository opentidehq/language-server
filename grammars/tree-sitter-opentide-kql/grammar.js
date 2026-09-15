/// <reference types="tree-sitter-cli/dsl" />
// @ts-check

/**
 * Tree-sitter grammar for Kusto Query Language (KQL) as used in Microsoft
 * Sentinel and Defender for Endpoint hunting queries.
 *
 * Control commands (`.show`, `.create`, …) are parsed so the engine can emit
 * `kql_control_command_unsupported`. They are not valid detection queries.
 * SQL is out of scope.
 */
module.exports = grammar({
  name: "opentide_kql",

  extras: ($) => [/\s/, $.comment],

  word: ($) => $.identifier,

  rules: {
    source_file: ($) =>
      seq(repeat($.let_statement), optional(choice($.query, $.control_command))),

    comment: (_) =>
      token(
        choice(seq("//", /.*/), seq("/*", /[^*]*\*+([^/*][^*]*\*+)*/, "/")),
      ),

    let_statement: ($) =>
      seq(
        "let",
        field("name", $.identifier),
        "=",
        field("value", $.expression),
        ";",
      ),

    query: ($) => field("body", $.tabular_expression),

    control_command: ($) =>
      seq(".", field("name", $.identifier), optional(repeat1($.identifier))),

    tabular_expression: ($) =>
      prec.left(
        seq(
          field("source", $.tabular_primary),
          repeat(seq("|", field("operator", $.tabular_operator))),
        ),
      ),

    tabular_primary: ($) =>
      choice(
        field("table", $.identifier),
        seq("(", $.tabular_expression, ")"),
        $.print_operator,
      ),

    tabular_operator: ($) =>
      choice(
        $.where_operator,
        $.project_operator,
        $.project_away_operator,
        $.project_rename_operator,
        $.extend_operator,
        $.summarize_operator,
        $.join_operator,
        $.union_operator,
        $.parse_operator,
        $.lookup_operator,
        $.take_operator,
        $.limit_operator,
        $.sort_operator,
        $.distinct_operator,
        $.render_operator,
        $.unknown_operator,
      ),

    where_operator: ($) => seq("where", field("predicate", $.expression)),

    project_operator: ($) =>
      seq("project", field("columns", commaSep1($.project_item))),

    project_away_operator: ($) =>
      seq("project-away", field("columns", commaSep1($.identifier))),

    project_rename_operator: ($) =>
      seq("project-rename", field("renames", commaSep1($.rename_item))),

    extend_operator: ($) =>
      seq("extend", field("assignments", commaSep1($.assignment))),

    summarize_operator: ($) =>
      seq(
        "summarize",
        field("aggregates", commaSep1($.expression)),
        optional(seq("by", field("by", commaSep1($.expression)))),
      ),

    join_operator: ($) =>
      seq(
        "join",
        optional(seq("kind", "=", field("kind", $.identifier))),
        field("right", $.tabular_primary),
        "on",
        field("condition", $.expression),
      ),

    union_operator: ($) =>
      seq("union", field("tables", commaSep1($.identifier))),

    parse_operator: ($) =>
      seq("parse", field("column", $.identifier), "with", field("pattern", $.string)),

    lookup_operator: ($) =>
      seq(
        "lookup",
        field("table", $.identifier),
        "on",
        field("condition", $.expression),
      ),

    take_operator: ($) => seq("take", field("count", $.number)),

    limit_operator: ($) => seq("limit", field("count", $.number)),

    sort_operator: ($) =>
      seq(
        choice("sort", "order"),
        optional("by"),
        field("keys", commaSep1($.sort_item)),
      ),

    sort_item: ($) => seq($.expression, optional(choice("asc", "desc"))),

    distinct_operator: ($) =>
      seq("distinct", optional(field("columns", commaSep1($.identifier)))),

    render_operator: ($) => seq("render", field("kind", $.identifier)),

    print_operator: ($) => seq("print", commaSep1($.expression)),

    unknown_operator: ($) =>
      seq(field("name", $.identifier), optional(field("args", $.expression))),

    project_item: ($) => choice($.assignment, $.identifier),

    rename_item: ($) =>
      seq(field("new", $.identifier), "=", field("old", $.identifier)),

    assignment: ($) =>
      seq(field("name", $.identifier), "=", field("value", $.expression)),

    expression: ($) => $.or_expression,

    or_expression: ($) =>
      prec.left(1, seq($.and_expression, repeat(seq("or", $.and_expression)))),

    and_expression: ($) =>
      prec.left(2, seq($.not_expression, repeat(seq("and", $.not_expression)))),

    not_expression: ($) =>
      choice(seq("not", $.comparison_expression), $.comparison_expression),

    comparison_expression: ($) =>
      prec.left(
        3,
        seq(
          $.additive_expression,
          optional(
            seq(
              choice(
                "==",
                "!=",
                "<>",
                "<",
                ">",
                "<=",
                ">=",
                "=~",
                "!~",
                "has",
                "contains",
                "startswith",
                "endswith",
                "in",
                "!in",
                "between",
              ),
              $.additive_expression,
            ),
          ),
        ),
      ),

    additive_expression: ($) =>
      prec.left(
        4,
        seq(
          $.multiplicative_expression,
          repeat(seq(choice("+", "-"), $.multiplicative_expression)),
        ),
      ),

    multiplicative_expression: ($) =>
      prec.left(
        5,
        seq($.unary_expression, repeat(seq(choice("*", "/", "%"), $.unary_expression))),
      ),

    unary_expression: ($) =>
      choice(seq(choice("-", "+"), $.primary_expression), $.primary_expression),

    primary_expression: ($) =>
      choice(
        $.function_call,
        $.identifier,
        $.string,
        $.number,
        $.boolean,
        $.null,
        $.timespan,
        seq("(", $.expression, ")"),
      ),

    function_call: ($) =>
      prec(
        10,
        seq(
          field("name", $.identifier),
          "(",
          field("arguments", optional(commaSep1($.expression))),
          ")",
        ),
      ),

    identifier: (_) => /[A-Za-z_][A-Za-z0-9_]*/,

    string: (_) =>
      token(
        choice(
          seq('"', repeat(choice(/[^"\\]/, /\\./)), '"'),
          seq("'", repeat(choice(/[^'\\]/, /\\./)), "'"),
          seq("@\"", repeat(/[^"]/), '"'),
          seq("@'", repeat(/[^']/), "'"),
        ),
      ),

    number: (_) => token(/[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?/),

    boolean: (_) => choice("true", "false"),

    null: (_) => "null",

    timespan: (_) => token(/[0-9]+(d|h|m|s|ms)/),
  },
});

function commaSep1(rule) {
  return seq(rule, repeat(seq(",", rule)));
}
