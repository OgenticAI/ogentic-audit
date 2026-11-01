# Verifying a release

**Status:** Draft. Describes signed releases (format `0x0002`, [spec v0.2](../spec/v0.2.md)), which need `ogentic-audit` **0.4.0 or later**. Earlier versions report these logs as damaged.

This guide is for someone who received a folder of released documents (a requester, an auditor, a lawyer, a court) and wants to know whether anything in it was changed after it was signed. You do not need any secret, you do not need to trust whoever gave you the folder, and you do not need the software that produced it.

## What you need

1. **The signer's key fingerprint, from the signer.** It is 64 characters, usually printed as 16 groups of 4, for example `6db5 e9b8 a1ba ce1c dd9a 7c6a db9e 9396 acc5 0734 65d9 fe8e 3a0e f6d9 c60d 6d4f`. Get it from the signer's website, a letter, a court filing, or a phone call. **Do not take it from the folder you are checking**: anyone who could change the folder could change a fingerprint printed inside it.
2. A computer with OpenSSH and Python 3. macOS and most Linux systems have both. Windows 10 and later include OpenSSH.
3. Optionally, the `ogentic-audit` verifier, to also check the audit log (step B).

## A. Check the signature and the files with standard tools

This uses only tools that come with your computer, so it does not depend on any software from the signer or from us. Do it first. It also checks any verifier program included in the folder before you run it.

Open a terminal in the release folder and follow [spec §11.7](../spec/v0.2.md#117-checking-a-release-with-stock-tools-only). In short:

1. Compare the folder's key with the fingerprint you were given. Let the computer compare them: the command prints `key matches` or `KEY DOES NOT MATCH`. People checking long numbers by eye tend to look at the first and last few characters, and those are exactly the ones a forger can match.
2. Check that the fingerprint is not one of the "weak" keys listed in [Appendix A](../spec/v0.2.md#appendix-a-small-order-encodings). A weak key lets anyone sign anything.
3. Run `ssh-keygen -Y verify`. `Good "ogentic-audit/v0.2/release" signature` means the list of files was signed by that key.
4. Run the file check. Every file prints `OK`; a changed file prints `FAILED` with its name; a missing file is reported as missing.

On Windows, use the PowerShell commands in the same section.

What this step does not check: individual rows inside an index file, the audit log, and key rotations or revocations. Step B checks those.

## B. Check everything with the verifier

1. **Get the verifier independently.** Download it from <https://github.com/OgenticAI/ogentic-audit/releases>, or install it with `cargo install ogentic-audit --locked` or `pip install ogentic-audit`. The release page publishes `SHA256SUMS` and a signature bundle for each download, which you can check offline as described in [spec §11.8](../spec/v0.2.md#118-obtaining-the-verifier). If you must use a verifier included in the folder, run it only after step A has passed.
2. Run:

   ```sh
   ogentic-audit verify-release <folder> --key-fingerprint "6db5 e9b8 a1ba ce1c dd9a 7c6a db9e 9396 acc5 0734 65d9 fe8e 3a0e f6d9 c60d 6d4f"
   ```

   Use the fingerprint you were given, in quotes, or with dashes instead of spaces. With Python: `python -m ogentic_audit verify-release <folder> --key-fingerprint "…"`. Add `--revocations <file>` for each revocation the signer has published, and `--expect-release-id <id>` if you know which release this should be.
3. To save the report: `ogentic-audit verify-release … > report.txt`, or add `--format json` for a machine-readable report.

## What the result means

| You see | Exit code | Meaning |
|---------|-----------|---------|
| `✓ Verified` | 0 | Every listed file, and every audit log up to the head named in the release, is exactly as signed by the key you supplied. |
| `✓ Verified … tail not anchored` (for a single log) | 0 | Everything checked is as signed, but records after the last one shown could have been removed. A release always anchors its logs at the signed head. |
| `! Not verified: you did not supply the signer's key` | 4 | The files match a signature, but you did not say whose signature to expect, so anyone could have made it. Get the fingerprint from the signer and run again. |
| `! Not verified: the audit log has no records` | 4 | There is nothing signed to check the key against. |
| `✗ Verification failed` | 1 | Something changed. The report lists each problem under **Altered** (which file, and which row of an index if the file has named rows), **Missing**, or **Not covered by the signature** (a file was added). |
| an error message | 2 or 3 | The check could not run: the folder could not be read (2), or an input was wrong, such as a mistyped fingerprint or an old-format log (3). This is not a finding about the release. |
| a usage message | 64 | The command was typed incorrectly. |

**Pages.** Each page released as its own file is named if it changes. A file that holds several pages (a multi-page PDF) is named as a whole: the report says the file changed, but cannot say which page.

**Withheld content.** A release may leave out the content of withheld records from its audit log. The report counts these records. They still verify: the signature covers a fingerprint of the withheld content, which a court reviewing the content privately can check.

## What verification does not prove

- **That what was recorded is true.** A signature shows who signed and that nothing changed since. It cannot show that the signer recorded events honestly.
- **When things happened.** Times in the log and the release come from the signer's own clock.
- **That nothing was removed from the end of a log**, unless the report says the log is anchored (always the case in a release, at its signed head).
- **That the key belongs to who you think.** That depends on where you got the fingerprint. Get it from the signer directly.
- **That the key had not been revoked**, unless you supplied the signer's published revocations.
- **Which page changed inside a multi-page file.**
