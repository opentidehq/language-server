(let_statement "let" @keyword)
(where_operator "where" @keyword)
(project_operator "project" @keyword)
(project_away_operator "project-away" @keyword)
(project_rename_operator "project-rename" @keyword)
(extend_operator "extend" @keyword)
(summarize_operator "summarize" @keyword)
(join_operator "join" @keyword)
(union_operator "union" @keyword)
(parse_operator "parse" @keyword)
(lookup_operator "lookup" @keyword)
(take_operator "take" @keyword)
(limit_operator "limit" @keyword)
(sort_operator "sort" @keyword)
(sort_operator "order" @keyword)
(distinct_operator "distinct" @keyword)
(render_operator "render" @keyword)
(print_operator "print" @keyword)
(control_command "." @error)
(control_command (identifier) @error)

"|" @operator.pipe

(function_call name: (identifier) @function)
(tabular_primary (identifier) @type)
(identifier) @variable
(string) @string
(number) @number
(boolean) @boolean
(null) @constant
(timespan) @number
(comment) @comment

"and" @keyword
"or" @operator
"not" @operator
"==" @operator
"!=" @operator
"=~" @operator
"(" @punctuation.bracket
")" @punctuation.bracket
"," @punctuation.delimiter
"=" @operator
";" @punctuation.delimiter
"by" @keyword
"on" @keyword
"with" @keyword
"kind" @keyword
"asc" @keyword
"desc" @keyword
