parser "def" {
    entrypoint "parse_def_file"
    stage "det/examples/def/compiled/lexer.stage" {
        filter "det/common/line_comments_token.det"
        filter "det/common/numeric_token.det"
        import "det/common/string_char.det" ["string_char"]
        import "det/common/double_string.det" ["any_double_string"]
        filter "det/common/any_double_string_token.det" {
        import "det/common/single_string.det" ["any_single_string"]
        filter "det/common/any_single_string_token.det"
        ;; "det/common/triple_double.det"
        ;; "det/common/triple_double_token.det"
        ;; "det/common/triple_single.det"
        ;; "det/common/triple_single_token.det"
        filter "det/examples/def/identifier_token.det"
        filter "det/common/whitespace_token.det"
        filter "det/common/copy_token.det"
    }
    stage "det/examples/def/compiled/syntax.stage" {
        parser "det/examples/def/syntax.det"
    }
}
