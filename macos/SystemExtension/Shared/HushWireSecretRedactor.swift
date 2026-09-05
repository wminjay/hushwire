import Foundation

enum HushWireRedactor {
  static func redact(_ text: String) -> String {
    // Remove the complete remainder of an assignment line. This is
    // intentionally conservative so malformed and triple-quoted TOML cannot
    // expose the part that a narrower string-literal regex failed to match.
    let patterns = [
      #"(?im)(\b(?:private_key|psk)\s*=\s*)[^\r\n]*"#,
      #"(?im)(\"(?:private_key|psk)\"\s*:\s*)[^\r\n]*"#,
    ]
    return patterns.reduce(text) { value, pattern in
      guard let expression = try? NSRegularExpression(pattern: pattern) else { return value }
      let range = NSRange(value.startIndex..<value.endIndex, in: value)
      return expression.stringByReplacingMatches(
        in: value,
        range: range,
        withTemplate: "$1\"<redacted>\""
      )
    }
  }
}
