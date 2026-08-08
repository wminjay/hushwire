import Foundation

struct CommandResult {
  let exitCode: Int32
  let output: String

  var succeeded: Bool { exitCode == 0 }
}

enum CommandRunner {
  static func run(executable: URL, arguments: [String]) -> CommandResult {
    let process = Process()
    let outputPipe = Pipe()

    process.executableURL = executable
    process.arguments = arguments
    process.standardOutput = outputPipe
    process.standardError = outputPipe

    do {
      try process.run()
      process.waitUntilExit()
      let data = outputPipe.fileHandleForReading.readDataToEndOfFile()
      let output = String(decoding: data, as: UTF8.self)
        .trimmingCharacters(in: .whitespacesAndNewlines)
      return CommandResult(exitCode: process.terminationStatus, output: output)
    } catch {
      return CommandResult(exitCode: 127, output: error.localizedDescription)
    }
  }

  /// Runs a bundled control command after macOS displays its standard
  /// administrator authorization dialog. Arguments are passed as AppleScript
  /// argv values and quoted by AppleScript, rather than interpolated into a
  /// shell string.
  static func runWithAdministratorPrivileges(arguments: [String]) -> CommandResult {
    let script = """
      on run argv
          set commandText to ""
          repeat with argumentValue in argv
              set commandText to commandText & quoted form of (contents of argumentValue) & " "
          end repeat
          do shell script commandText with administrator privileges
      end run
      """

    return run(
      executable: URL(fileURLWithPath: "/usr/bin/osascript"),
      arguments: ["-e", script, "--"] + arguments
    )
  }
}
