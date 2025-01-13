# Print an optspec for argparse to handle cmd's options that are independent of any subcommand.
function __fish_sq_global_optspecs
	string join \n cli-version= overwrite home= key-store= cert-store= keyring= known-notation= time= policy-as-of= trust-root= password-file= v/verbose q/quiet batch h/help
end

function __fish_sq_needs_command
	# Figure out if the current invocation already has a command.
	set -l cmd (commandline -opc)
	set -e cmd[1]
	argparse -s (__fish_sq_global_optspecs) -- $cmd 2>/dev/null
	or return
	if set -q argv[1]
		# Also print the command, so this can be used to figure out what it is.
		echo $argv[1]
		return 1
	end
	return 0
end

function __fish_sq_using_subcommand
	set -l cmd (__fish_sq_needs_command)
	test -z "$cmd"
	and return 1
	contains -- $cmd[1] $argv
end

complete -c sq -n "__fish_sq_needs_command" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_needs_command" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_needs_command" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_needs_command" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_needs_command" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_needs_command" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_needs_command" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_needs_command" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_needs_command" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_needs_command" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_needs_command" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_needs_command" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_needs_command" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_needs_command" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_needs_command" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_needs_command" -f -a "encrypt" -d 'Encrypt a message'
complete -c sq -n "__fish_sq_needs_command" -f -a "decrypt" -d 'Decrypt a message'
complete -c sq -n "__fish_sq_needs_command" -f -a "sign" -d 'Sign messages or data files'
complete -c sq -n "__fish_sq_needs_command" -f -a "verify" -d 'Verify signed messages or detached signatures'
complete -c sq -n "__fish_sq_needs_command" -f -a "download" -d 'Download and authenticate the data'
complete -c sq -n "__fish_sq_needs_command" -f -a "inspect" -d 'Inspect data, like file(1)'
complete -c sq -n "__fish_sq_needs_command" -f -a "cert" -d 'Manage certificates'
complete -c sq -n "__fish_sq_needs_command" -f -a "key" -d 'Manage keys'
complete -c sq -n "__fish_sq_needs_command" -f -a "pki" -d 'Authenticate certs using the Web of Trust'
complete -c sq -n "__fish_sq_needs_command" -f -a "network" -d 'Retrieve and publish certificates over the network'
complete -c sq -n "__fish_sq_needs_command" -f -a "keyring" -d 'Manage collections of keys or certs'
complete -c sq -n "__fish_sq_needs_command" -f -a "packet" -d 'Low-level packet manipulation'
complete -c sq -n "__fish_sq_needs_command" -f -a "config" -d 'Get configuration options'
complete -c sq -n "__fish_sq_needs_command" -f -a "version" -d 'Detailed version and output version information'
complete -c sq -n "__fish_sq_needs_command" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sq -n "__fish_sq_using_subcommand encrypt" -l output -d 'Write to FILE or stdout if omitted' -r
complete -c sq -n "__fish_sq_using_subcommand encrypt" -l for -d 'Use certificates with the specified fingerprint or key ID' -r
complete -c sq -n "__fish_sq_using_subcommand encrypt" -l for-userid -d 'Use certificates with the specified user ID' -r
complete -c sq -n "__fish_sq_using_subcommand encrypt" -l for-email -d 'Use certificates where a user ID includes the specified email address' -r
complete -c sq -n "__fish_sq_using_subcommand encrypt" -l for-file -d 'Read certificates from PATH' -r -F
complete -c sq -n "__fish_sq_using_subcommand encrypt" -l with-password-file -d 'File containing password to encrypt the message' -r -F
complete -c sq -n "__fish_sq_using_subcommand encrypt" -l set-metadata-filename -d 'Set the filename of the encrypted file as metadata' -r
complete -c sq -n "__fish_sq_using_subcommand encrypt" -l signer -d 'Sign the message using the key with the specified fingerprint or key ID' -r
complete -c sq -n "__fish_sq_using_subcommand encrypt" -l signer-userid -d 'Sign the message using the key with the specified user ID' -r
complete -c sq -n "__fish_sq_using_subcommand encrypt" -l signer-email -d 'Sign the message using the key where a user ID includes the specified email address' -r
complete -c sq -n "__fish_sq_using_subcommand encrypt" -l signer-file -d 'Sign the message using the key read from PATH' -r -F
complete -c sq -n "__fish_sq_using_subcommand encrypt" -l signature-notation -d 'Add a notation to the signature.' -r
complete -c sq -n "__fish_sq_using_subcommand encrypt" -l encrypt-for -d 'Select what kind of keys are considered for encryption.' -r -f -a "{transport\t'Protects data in transport',storage\t'Protects data at rest',universal\t'Protects data in transport and at rest'}"
complete -c sq -n "__fish_sq_using_subcommand encrypt" -l compression -d 'Select compression scheme to use' -r -f -a "{none\t'',zip\t'',zlib\t'',bzip2\t''}"
complete -c sq -n "__fish_sq_using_subcommand encrypt" -l profile -d 'Select the OpenPGP standard for the encryption container' -r -f -a "{rfc4880\t'RFC4880, published in 2007, defines "v4" OpenPGP'}"
complete -c sq -n "__fish_sq_using_subcommand encrypt" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand encrypt" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand encrypt" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand encrypt" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand encrypt" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand encrypt" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand encrypt" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand encrypt" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand encrypt" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand encrypt" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand encrypt" -l binary -d 'Emit binary data'
complete -c sq -n "__fish_sq_using_subcommand encrypt" -l for-self -d 'Encrypt the message for yourself'
complete -c sq -n "__fish_sq_using_subcommand encrypt" -l with-password -d 'Prompt to add a password to encrypt with'
complete -c sq -n "__fish_sq_using_subcommand encrypt" -l signer-self -d 'Sign using your default signer keys'
complete -c sq -n "__fish_sq_using_subcommand encrypt" -l use-expired-subkey -d 'Fall back to expired encryption subkeys'
complete -c sq -n "__fish_sq_using_subcommand encrypt" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand encrypt" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand encrypt" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand encrypt" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand encrypt" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand decrypt" -l output -d 'Write to FILE or stdout if omitted' -r
complete -c sq -n "__fish_sq_using_subcommand decrypt" -l signatures -d 'Set the threshold of valid signatures to N' -r
complete -c sq -n "__fish_sq_using_subcommand decrypt" -l signer -d 'Require a signature from a certificate with the specified fingerprint or key ID' -r
complete -c sq -n "__fish_sq_using_subcommand decrypt" -l signer-userid -d 'Require a signature from a certificate with the specified user ID' -r
complete -c sq -n "__fish_sq_using_subcommand decrypt" -l signer-email -d 'Require a signature from a certificate where a user ID includes the specified email address' -r
complete -c sq -n "__fish_sq_using_subcommand decrypt" -l signer-domain -d 'Require a signature from a certificate where a user ID includes an email address for the specified domain' -r
complete -c sq -n "__fish_sq_using_subcommand decrypt" -l signer-file -d 'Require a signature from a certificate read from PATH' -r -F
complete -c sq -n "__fish_sq_using_subcommand decrypt" -l recipient-file -d 'Decrypt the message using the key in KEY_FILE' -r -F
complete -c sq -n "__fish_sq_using_subcommand decrypt" -l session-key -d 'Decrypt an encrypted message using SESSION-KEY' -r
complete -c sq -n "__fish_sq_using_subcommand decrypt" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand decrypt" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand decrypt" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand decrypt" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand decrypt" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand decrypt" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand decrypt" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand decrypt" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand decrypt" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand decrypt" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand decrypt" -l dump-session-key -d 'Print the session key to stderr'
complete -c sq -n "__fish_sq_using_subcommand decrypt" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand decrypt" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand decrypt" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand decrypt" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand decrypt" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand sign" -l output -d 'Write to FILE or stdout if omitted' -r
complete -c sq -n "__fish_sq_using_subcommand sign" -l signature-file -d 'Create a detached signature file' -r
complete -c sq -n "__fish_sq_using_subcommand sign" -l mode -d 'Select the signature mode' -r -f -a "{binary\t'Create binary signatures',text\t'Create text signatures'}"
complete -c sq -n "__fish_sq_using_subcommand sign" -l merge -d 'Merge signatures from the input and SIGNED-MESSAGE' -r -F
complete -c sq -n "__fish_sq_using_subcommand sign" -l signer -d 'Create the signature using the key with the specified fingerprint or key ID' -r
complete -c sq -n "__fish_sq_using_subcommand sign" -l signer-userid -d 'Create the signature using the key with the specified user ID' -r
complete -c sq -n "__fish_sq_using_subcommand sign" -l signer-email -d 'Create the signature using the key where a user ID includes the specified email address' -r
complete -c sq -n "__fish_sq_using_subcommand sign" -l signer-file -d 'Create the signature using the key read from PATH' -r -F
complete -c sq -n "__fish_sq_using_subcommand sign" -l signature-notation -d 'Add a notation to the signature.' -r
complete -c sq -n "__fish_sq_using_subcommand sign" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand sign" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand sign" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand sign" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand sign" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand sign" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand sign" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand sign" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand sign" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand sign" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand sign" -l binary -d 'Emit binary data'
complete -c sq -n "__fish_sq_using_subcommand sign" -l message -d 'Create an inline-signed message'
complete -c sq -n "__fish_sq_using_subcommand sign" -l cleartext -d 'Create a cleartext-signed message'
complete -c sq -n "__fish_sq_using_subcommand sign" -l append -d 'Append a signature to existing signature'
complete -c sq -n "__fish_sq_using_subcommand sign" -l notarize -d 'Sign a message and all existing signatures'
complete -c sq -n "__fish_sq_using_subcommand sign" -l signer-self -d 'Sign using your default signer keys'
complete -c sq -n "__fish_sq_using_subcommand sign" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand sign" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand sign" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand sign" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand sign" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand verify" -l output -d 'Write to FILE or stdout if omitted' -r
complete -c sq -n "__fish_sq_using_subcommand verify" -l signature-file -d 'Verify a detached signature file' -r -F
complete -c sq -n "__fish_sq_using_subcommand verify" -l signatures -d 'Set the threshold of valid signatures to N' -r
complete -c sq -n "__fish_sq_using_subcommand verify" -l signer -d 'Require a signature from a certificate with the specified fingerprint or key ID' -r
complete -c sq -n "__fish_sq_using_subcommand verify" -l signer-userid -d 'Require a signature from a certificate with the specified user ID' -r
complete -c sq -n "__fish_sq_using_subcommand verify" -l signer-email -d 'Require a signature from a certificate where a user ID includes the specified email address' -r
complete -c sq -n "__fish_sq_using_subcommand verify" -l signer-domain -d 'Require a signature from a certificate where a user ID includes an email address for the specified domain' -r
complete -c sq -n "__fish_sq_using_subcommand verify" -l signer-file -d 'Require a signature from a certificate read from PATH' -r -F
complete -c sq -n "__fish_sq_using_subcommand verify" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand verify" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand verify" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand verify" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand verify" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand verify" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand verify" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand verify" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand verify" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand verify" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand verify" -l message -d 'Verify an inline signed message'
complete -c sq -n "__fish_sq_using_subcommand verify" -l cleartext -d 'Verify a cleartext-signed message'
complete -c sq -n "__fish_sq_using_subcommand verify" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand verify" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand verify" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand verify" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand verify" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand download" -l url -d 'The data to download' -r
complete -c sq -n "__fish_sq_using_subcommand download" -l signature -d 'URL of the signature' -r
complete -c sq -n "__fish_sq_using_subcommand download" -l signer -d 'Require a signature from a certificate with the specified fingerprint or key ID' -r
complete -c sq -n "__fish_sq_using_subcommand download" -l signer-userid -d 'Require a signature from a certificate with the specified user ID' -r
complete -c sq -n "__fish_sq_using_subcommand download" -l signer-email -d 'Require a signature from a certificate where a user ID includes the specified email address' -r
complete -c sq -n "__fish_sq_using_subcommand download" -l signer-domain -d 'Require a signature from a certificate where a user ID includes an email address for the specified domain' -r
complete -c sq -n "__fish_sq_using_subcommand download" -l signer-file -d 'Require a signature from a certificate read from PATH' -r -F
complete -c sq -n "__fish_sq_using_subcommand download" -l signatures -d 'Set the threshold of valid signatures to N' -r
complete -c sq -n "__fish_sq_using_subcommand download" -l output -d 'Write to FILE or stdout if FILE is \'-\'' -r
complete -c sq -n "__fish_sq_using_subcommand download" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand download" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand download" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand download" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand download" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand download" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand download" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand download" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand download" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand download" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand download" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand download" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand download" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand download" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand download" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand inspect" -l cert -d 'Inspect certificates with the specified fingerprint or key ID' -r
complete -c sq -n "__fish_sq_using_subcommand inspect" -l cert-userid -d 'Inspect certificates with the specified user ID.  Note: User IDs are not authenticated.' -r
complete -c sq -n "__fish_sq_using_subcommand inspect" -l cert-email -d 'Inspect certificates where a user ID includes the specified email address.  Note: User IDs are not authenticated.' -r
complete -c sq -n "__fish_sq_using_subcommand inspect" -l cert-domain -d 'Inspect certificates where a user ID includes an email address for the specified domain.  Note: User IDs are not authenticated.' -r
complete -c sq -n "__fish_sq_using_subcommand inspect" -l cert-grep -d 'Inspect certificates with a user ID that matches the pattern, case insensitively.  Note: User IDs are not authenticated.' -r
complete -c sq -n "__fish_sq_using_subcommand inspect" -l cert-file -d 'Read certificates from PATH' -r -F
complete -c sq -n "__fish_sq_using_subcommand inspect" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand inspect" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand inspect" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand inspect" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand inspect" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand inspect" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand inspect" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand inspect" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand inspect" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand inspect" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand inspect" -l certifications -d 'Print third-party certifications'
complete -c sq -n "__fish_sq_using_subcommand inspect" -l dump-bad-signatures -d 'Dump signatures that are definitively bad'
complete -c sq -n "__fish_sq_using_subcommand inspect" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand inspect" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand inspect" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand inspect" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand inspect" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand cert; and not __fish_seen_subcommand_from import export list lint" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and not __fish_seen_subcommand_from import export list lint" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and not __fish_seen_subcommand_from import export list lint" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and not __fish_seen_subcommand_from import export list lint" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and not __fish_seen_subcommand_from import export list lint" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand cert; and not __fish_seen_subcommand_from import export list lint" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and not __fish_seen_subcommand_from import export list lint" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and not __fish_seen_subcommand_from import export list lint" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and not __fish_seen_subcommand_from import export list lint" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and not __fish_seen_subcommand_from import export list lint" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand cert; and not __fish_seen_subcommand_from import export list lint" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand cert; and not __fish_seen_subcommand_from import export list lint" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand cert; and not __fish_seen_subcommand_from import export list lint" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand cert; and not __fish_seen_subcommand_from import export list lint" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand cert; and not __fish_seen_subcommand_from import export list lint" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand cert; and not __fish_seen_subcommand_from import export list lint" -f -a "import" -d 'Import certificates into the local certificate store'
complete -c sq -n "__fish_sq_using_subcommand cert; and not __fish_seen_subcommand_from import export list lint" -f -a "export" -d 'Export certificates from the local certificate store'
complete -c sq -n "__fish_sq_using_subcommand cert; and not __fish_seen_subcommand_from import export list lint" -f -a "list" -d 'List all authenticated bindings (User ID and certificate pairs)'
complete -c sq -n "__fish_sq_using_subcommand cert; and not __fish_seen_subcommand_from import export list lint" -f -a "lint" -d 'Check certificates for issues'
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from import" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from import" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from import" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from import" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from import" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from import" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from import" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from import" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from import" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from import" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from import" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from import" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from import" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from import" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from import" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from export" -l output -d 'Write to FILE or stdout if omitted' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from export" -l cert -d 'Use certificates with the specified fingerprint or key ID' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from export" -l cert-userid -d 'Use certificates with the specified user ID' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from export" -l cert-email -d 'Use certificates where a user ID includes the specified email address' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from export" -l cert-domain -d 'Use certificates where a user ID includes an email address for the specified domain' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from export" -l cert-grep -d 'Use certificates with a user ID that matches the pattern, case insensitively' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from export" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from export" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from export" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from export" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from export" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from export" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from export" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from export" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from export" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from export" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from export" -l local -d 'Export local (non-exportable) signatures'
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from export" -l all -d 'Export all certificates'
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from export" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from export" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from export" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from export" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from export" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from list" -l userid -d 'Use the specified user ID' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from list" -l email -d 'Use a user ID with the specified email address' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from list" -l amount -d 'The required amount of trust' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from list" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from list" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from list" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from list" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from list" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from list" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from list" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from list" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from list" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from list" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from list" -l show-paths -d 'Show why a binding is authenticated'
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from list" -l gossip -d 'Treats all certificates as unreliable trust roots'
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from list" -l certification-network -d 'Treats the network as a certification network'
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from list" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from list" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from list" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from list" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from list" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from lint" -l cert -d 'Use certificates with the specified fingerprint or key ID' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from lint" -l cert-userid -d 'Use certificates with the specified user ID' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from lint" -l cert-email -d 'Use certificates where a user ID includes the specified email address' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from lint" -l cert-domain -d 'Use certificates where a user ID includes an email address for the specified domain' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from lint" -l cert-grep -d 'Use certificates with a user ID that matches the pattern, case insensitively' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from lint" -l cert-file -d 'Read certificates from PATH' -r -F
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from lint" -l output -d 'Write to the specified FILE.  If not specified, and the certificate was read from the certificate store, imports the modified certificate into the cert store.  If not specified, and the certificate was read from a file, writes the modified certificate to stdout.' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from lint" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from lint" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from lint" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from lint" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from lint" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from lint" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from lint" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from lint" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from lint" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from lint" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from lint" -l fix -d 'Attempts to fix certificates, when possible'
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from lint" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from lint" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from lint" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from lint" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand cert; and __fish_seen_subcommand_from lint" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand key; and not __fish_seen_subcommand_from list generate import export delete password expire revoke userid subkey approvals" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand key; and not __fish_seen_subcommand_from list generate import export delete password expire revoke userid subkey approvals" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand key; and not __fish_seen_subcommand_from list generate import export delete password expire revoke userid subkey approvals" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand key; and not __fish_seen_subcommand_from list generate import export delete password expire revoke userid subkey approvals" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand key; and not __fish_seen_subcommand_from list generate import export delete password expire revoke userid subkey approvals" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand key; and not __fish_seen_subcommand_from list generate import export delete password expire revoke userid subkey approvals" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand key; and not __fish_seen_subcommand_from list generate import export delete password expire revoke userid subkey approvals" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand key; and not __fish_seen_subcommand_from list generate import export delete password expire revoke userid subkey approvals" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand key; and not __fish_seen_subcommand_from list generate import export delete password expire revoke userid subkey approvals" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand key; and not __fish_seen_subcommand_from list generate import export delete password expire revoke userid subkey approvals" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand key; and not __fish_seen_subcommand_from list generate import export delete password expire revoke userid subkey approvals" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand key; and not __fish_seen_subcommand_from list generate import export delete password expire revoke userid subkey approvals" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand key; and not __fish_seen_subcommand_from list generate import export delete password expire revoke userid subkey approvals" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand key; and not __fish_seen_subcommand_from list generate import export delete password expire revoke userid subkey approvals" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand key; and not __fish_seen_subcommand_from list generate import export delete password expire revoke userid subkey approvals" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand key; and not __fish_seen_subcommand_from list generate import export delete password expire revoke userid subkey approvals" -f -a "list" -d 'List keys managed by the key store'
complete -c sq -n "__fish_sq_using_subcommand key; and not __fish_seen_subcommand_from list generate import export delete password expire revoke userid subkey approvals" -f -a "generate" -d 'Generate a new key'
complete -c sq -n "__fish_sq_using_subcommand key; and not __fish_seen_subcommand_from list generate import export delete password expire revoke userid subkey approvals" -f -a "import" -d 'Import keys into the key store'
complete -c sq -n "__fish_sq_using_subcommand key; and not __fish_seen_subcommand_from list generate import export delete password expire revoke userid subkey approvals" -f -a "export" -d 'Export keys from the key store'
complete -c sq -n "__fish_sq_using_subcommand key; and not __fish_seen_subcommand_from list generate import export delete password expire revoke userid subkey approvals" -f -a "delete" -d 'Delete a certificate\'s secret key material'
complete -c sq -n "__fish_sq_using_subcommand key; and not __fish_seen_subcommand_from list generate import export delete password expire revoke userid subkey approvals" -f -a "password" -d 'Change the password protecting secret key material'
complete -c sq -n "__fish_sq_using_subcommand key; and not __fish_seen_subcommand_from list generate import export delete password expire revoke userid subkey approvals" -f -a "expire" -d 'Change a certificate\'s expiration time'
complete -c sq -n "__fish_sq_using_subcommand key; and not __fish_seen_subcommand_from list generate import export delete password expire revoke userid subkey approvals" -f -a "revoke" -d 'Revoke a certificate'
complete -c sq -n "__fish_sq_using_subcommand key; and not __fish_seen_subcommand_from list generate import export delete password expire revoke userid subkey approvals" -f -a "userid" -d 'Manage User IDs'
complete -c sq -n "__fish_sq_using_subcommand key; and not __fish_seen_subcommand_from list generate import export delete password expire revoke userid subkey approvals" -f -a "subkey" -d 'Manage subkeys'
complete -c sq -n "__fish_sq_using_subcommand key; and not __fish_seen_subcommand_from list generate import export delete password expire revoke userid subkey approvals" -f -a "approvals" -d 'Manages certification approvals'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from list" -l cert -d 'List keys with the specified fingerprint or key ID' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from list" -l cert-userid -d 'List keys with the specified user ID' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from list" -l cert-email -d 'List keys where a user ID includes the specified email address' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from list" -l cert-domain -d 'List keys where a user ID includes an email address for the specified domain' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from list" -l cert-grep -d 'List keys with a user ID that matches the pattern, case insensitively' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from list" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from list" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from list" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from list" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from list" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from list" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from list" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from list" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from list" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from list" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from list" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from list" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from list" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from list" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from list" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -l name -d 'Add a name as user ID to the key' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -l email -d 'Add an email address as user ID to the key' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -l userid -d 'Add a user ID to the key' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -l cipher-suite -d 'Select the cryptographic algorithms for the key  The default can be changed in the configuration file using the setting `key.generate.cipher-suite`.' -r -f -a "{rsa2k\t'',rsa3k\t'',rsa4k\t'',cv25519\t''}"
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -l profile -d 'Select the OpenPGP standard for the key' -r -f -a "{rfc4880\t'RFC4880, published in 2007, defines "v4" OpenPGP'}"
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -l new-password-file -d 'File containing password to encrypt the secret key material' -r -F
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -l can-encrypt -d 'Add an encryption-capable subkey [default: universal]' -r -f -a "{transport\t'Protects data in transport',storage\t'Protects data at rest',universal\t'Protects data in transport and at rest'}"
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -l output -d 'Write the key to the specified file' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -l rev-cert -d 'Write the emergency revocation certificate to FILE' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -l expiration -d 'Sets the expiration time' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -l own-key -d 'Mark the key as one\'s own key'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -l shared-key -d 'Mark the key as a shared key'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -l allow-non-canonical-userids -d 'Don\'t reject user IDs that are not in canonical form'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -l no-userids -d 'Create a key without any user IDs'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -l without-password -d 'Don\'t protect the secret key material with a password'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -l can-sign -d 'Add a signing-capable subkey (default)'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -l cannot-sign -d 'Don\'t add a signing-capable subkey'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -l can-authenticate -d 'Add an authentication-capable subkey (default)'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -l cannot-authenticate -d 'Don\'t add an authentication-capable subkey'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -l cannot-encrypt -d 'Don\'t add an encryption-capable subkey'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from generate" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from import" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from import" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from import" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from import" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from import" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from import" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from import" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from import" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from import" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from import" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from import" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from import" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from import" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from import" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from import" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from export" -l cert -d 'Export keys with the specified fingerprint or key ID' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from export" -l cert-userid -d 'Export keys with the specified user ID' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from export" -l cert-email -d 'Export keys where a user ID includes the specified email address' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from export" -l cert-domain -d 'Export keys where a user ID includes an email address for the specified domain' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from export" -l cert-grep -d 'Export keys with a user ID that matches the pattern, case insensitively' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from export" -l output -d 'Write to FILE or stdout if omitted' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from export" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from export" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from export" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from export" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from export" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from export" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from export" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from export" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from export" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from export" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from export" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from export" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from export" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from export" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from export" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from delete" -l cert -d 'Delete secret key material from the key with the specified fingerprint or key ID' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from delete" -l cert-userid -d 'Delete secret key material from the key with the specified user ID' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from delete" -l cert-email -d 'Delete secret key material from the key where a user ID includes the specified email address' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from delete" -l cert-file -d 'Delete the secret key material from the key read from PATH' -r -F
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from delete" -l output -d 'Write the stripped certificate to the specified file' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from delete" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from delete" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from delete" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from delete" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from delete" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from delete" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from delete" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from delete" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from delete" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from delete" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from delete" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from delete" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from delete" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from delete" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from delete" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from password" -l cert -d 'Change the password for the secret key material from the key with the specified fingerprint or key ID' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from password" -l cert-userid -d 'Change the password for the secret key material from the key with the specified user ID' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from password" -l cert-email -d 'Change the password for the secret key material from the key where a user ID includes the specified email address' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from password" -l cert-file -d 'Change the password for the secret key material from the key read from PATH' -r -F
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from password" -l new-password-file -d 'File containing password to encrypt the secret key material' -r -F
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from password" -l output -d 'Write to FILE or stdout if omitted' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from password" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from password" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from password" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from password" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from password" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from password" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from password" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from password" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from password" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from password" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from password" -l clear-password -d 'Clear the password protecting the secret key material'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from password" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from password" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from password" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from password" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from password" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from expire" -l cert -d 'Change the expiration of the key with the specified fingerprint or key ID' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from expire" -l cert-userid -d 'Change the expiration of the key with the specified user ID' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from expire" -l cert-email -d 'Change the expiration of the key where a user ID includes the specified email address' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from expire" -l cert-file -d 'Change the expiration of the key read from PATH' -r -F
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from expire" -l output -d 'Write to FILE or stdout if omitted' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from expire" -l expiration -d 'Sets the expiration time' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from expire" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from expire" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from expire" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from expire" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from expire" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from expire" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from expire" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from expire" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from expire" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from expire" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from expire" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from expire" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from expire" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from expire" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from expire" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from revoke" -l cert -d 'Revoke the key with the specified fingerprint or key ID' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from revoke" -l cert-userid -d 'Revoke the key with the specified user ID' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from revoke" -l cert-email -d 'Revoke the key where a user ID includes the specified email address' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from revoke" -l cert-file -d 'Revoke the key read from PATH' -r -F
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from revoke" -l revoker -d 'Use key with the specified fingerprint or key ID to create the revocation certificate.  Sign the revocation certificate using the specified key.  By default, the certificate being revoked is used.  Using this option, it is possible to create a third-party revocation.' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from revoke" -l revoker-userid -d 'Use key with the specified user ID to create the revocation certificate.  Sign the revocation certificate using the specified key.  By default, the certificate being revoked is used.  Using this option, it is possible to create a third-party revocation.' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from revoke" -l revoker-email -d 'Use key where a user ID includes the specified email address to create the revocation certificate.  Sign the revocation certificate using the specified key.  By default, the certificate being revoked is used.  Using this option, it is possible to create a third-party revocation.' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from revoke" -l revoker-file -d 'Read key from PATH to create the revocation certificate.  Sign the revocation certificate using the specified key.  By default, the certificate being revoked is used.  Using this option, it is possible to create a third-party revocation.' -r -F
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from revoke" -l reason -d 'The reason for the revocation' -r -f -a "{compromised\t'The secret key material may have been compromised.  Prefer this value if you suspect that the secret key has been leaked',superseded\t'The owner of the certificate has a new certificate.  Prefer `compromised` if the secret key material has been compromised even if the certificate is also being replaced!  You should include the fingerprint of the new certificate in the message',retired\t'The certificate should not be used anymore, and there is no replacement.  This is appropriate when someone leaves an organisation.  Prefer `compromised` if the secret key material has been compromised even if the certificate is also being retired!  You should include how to contact the owner, or who to contact instead in the message',unspecified\t'None of the other reasons apply.  OpenPGP implementations conservatively treat this type of revocation similar to a compromised key'}"
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from revoke" -l message -d 'A short, explanatory text' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from revoke" -l signature-notation -d 'Add a notation to the revocation' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from revoke" -l output -d 'Write to the specified FILE' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from revoke" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from revoke" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from revoke" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from revoke" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from revoke" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from revoke" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from revoke" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from revoke" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from revoke" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from revoke" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from revoke" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from revoke" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from revoke" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from revoke" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from revoke" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from userid" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from userid" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from userid" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from userid" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from userid" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from userid" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from userid" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from userid" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from userid" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from userid" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from userid" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from userid" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from userid" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from userid" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from userid" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from userid" -f -a "add" -d 'Add a user ID'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from userid" -f -a "revoke" -d 'Revoke a user ID'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from subkey" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from subkey" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from subkey" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from subkey" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from subkey" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from subkey" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from subkey" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from subkey" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from subkey" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from subkey" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from subkey" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from subkey" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from subkey" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from subkey" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from subkey" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from subkey" -f -a "add" -d 'Add a new subkey to a certificate'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from subkey" -f -a "export" -d 'Export keys from the key store'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from subkey" -f -a "delete" -d 'Delete a certificate\'s secret key material'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from subkey" -f -a "password" -d 'Change the password protecting secret key material'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from subkey" -f -a "expire" -d 'Change a subkey\'s expiration time'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from subkey" -f -a "revoke" -d 'Revoke a subkey'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from subkey" -f -a "bind" -d 'Bind keys from one certificate to another'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from approvals" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from approvals" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from approvals" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from approvals" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from approvals" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from approvals" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from approvals" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from approvals" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from approvals" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from approvals" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from approvals" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from approvals" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from approvals" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from approvals" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from approvals" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from approvals" -f -a "list" -d 'Lists third-party certifications'
complete -c sq -n "__fish_sq_using_subcommand key; and __fish_seen_subcommand_from approvals" -f -a "update" -d 'Approves of third-party certifications'
complete -c sq -n "__fish_sq_using_subcommand pki; and not __fish_seen_subcommand_from authenticate lookup identify vouch link path" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and not __fish_seen_subcommand_from authenticate lookup identify vouch link path" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and not __fish_seen_subcommand_from authenticate lookup identify vouch link path" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and not __fish_seen_subcommand_from authenticate lookup identify vouch link path" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and not __fish_seen_subcommand_from authenticate lookup identify vouch link path" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand pki; and not __fish_seen_subcommand_from authenticate lookup identify vouch link path" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and not __fish_seen_subcommand_from authenticate lookup identify vouch link path" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and not __fish_seen_subcommand_from authenticate lookup identify vouch link path" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and not __fish_seen_subcommand_from authenticate lookup identify vouch link path" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and not __fish_seen_subcommand_from authenticate lookup identify vouch link path" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand pki; and not __fish_seen_subcommand_from authenticate lookup identify vouch link path" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand pki; and not __fish_seen_subcommand_from authenticate lookup identify vouch link path" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand pki; and not __fish_seen_subcommand_from authenticate lookup identify vouch link path" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand pki; and not __fish_seen_subcommand_from authenticate lookup identify vouch link path" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand pki; and not __fish_seen_subcommand_from authenticate lookup identify vouch link path" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand pki; and not __fish_seen_subcommand_from authenticate lookup identify vouch link path" -f -a "authenticate" -d 'Authenticate a binding'
complete -c sq -n "__fish_sq_using_subcommand pki; and not __fish_seen_subcommand_from authenticate lookup identify vouch link path" -f -a "lookup" -d 'Lookup the certificates associated with a User ID'
complete -c sq -n "__fish_sq_using_subcommand pki; and not __fish_seen_subcommand_from authenticate lookup identify vouch link path" -f -a "identify" -d 'Identify a certificate'
complete -c sq -n "__fish_sq_using_subcommand pki; and not __fish_seen_subcommand_from authenticate lookup identify vouch link path" -f -a "vouch" -d 'Manage certifications'
complete -c sq -n "__fish_sq_using_subcommand pki; and not __fish_seen_subcommand_from authenticate lookup identify vouch link path" -f -a "link" -d 'Manage authenticated certificate and User ID links'
complete -c sq -n "__fish_sq_using_subcommand pki; and not __fish_seen_subcommand_from authenticate lookup identify vouch link path" -f -a "path" -d 'Verify the specified path'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from authenticate" -l cert -d 'Use certificates with the specified fingerprint or key ID' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from authenticate" -l userid -d 'Use the specified user ID' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from authenticate" -l email -d 'Use a user ID with the specified email address' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from authenticate" -l amount -d 'The required amount of trust' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from authenticate" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from authenticate" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from authenticate" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from authenticate" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from authenticate" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from authenticate" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from authenticate" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from authenticate" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from authenticate" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from authenticate" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from authenticate" -l show-paths -d 'Show why a binding is authenticated'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from authenticate" -l gossip -d 'Treats all certificates as unreliable trust roots'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from authenticate" -l certification-network -d 'Treats the network as a certification network'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from authenticate" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from authenticate" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from authenticate" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from authenticate" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from authenticate" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from lookup" -l userid -d 'Use the specified user ID' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from lookup" -l email -d 'Use a user ID with the specified email address' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from lookup" -l amount -d 'The required amount of trust' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from lookup" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from lookup" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from lookup" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from lookup" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from lookup" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from lookup" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from lookup" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from lookup" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from lookup" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from lookup" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from lookup" -l show-paths -d 'Show why a binding is authenticated'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from lookup" -l gossip -d 'Treats all certificates as unreliable trust roots'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from lookup" -l certification-network -d 'Treats the network as a certification network'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from lookup" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from lookup" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from lookup" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from lookup" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from lookup" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from identify" -l cert -d 'Use certificates with the specified fingerprint or key ID' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from identify" -l amount -d 'The required amount of trust' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from identify" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from identify" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from identify" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from identify" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from identify" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from identify" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from identify" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from identify" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from identify" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from identify" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from identify" -l show-paths -d 'Show why a binding is authenticated'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from identify" -l gossip -d 'Treats all certificates as unreliable trust roots'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from identify" -l certification-network -d 'Treats the network as a certification network'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from identify" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from identify" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from identify" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from identify" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from identify" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from vouch" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from vouch" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from vouch" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from vouch" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from vouch" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from vouch" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from vouch" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from vouch" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from vouch" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from vouch" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from vouch" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from vouch" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from vouch" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from vouch" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from vouch" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from vouch" -f -a "add" -d 'Certify a User ID for a Certificate'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from vouch" -f -a "authorize" -d 'Mark a certificate as a trusted introducer'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from link" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from link" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from link" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from link" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from link" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from link" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from link" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from link" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from link" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from link" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from link" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from link" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from link" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from link" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from link" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from link" -f -a "add" -d 'Link a certificate and a user ID'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from link" -f -a "authorize" -d 'Make a certificate a trusted introducer'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from link" -f -a "retract" -d 'Retract links'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from link" -f -a "list" -d 'List links'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from path" -l userid -d 'Use the specified user ID' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from path" -l email -d 'Use a user ID with the specified email address' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from path" -l name -d 'Use a user ID with the specified display name' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from path" -l amount -d 'The required amount of trust' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from path" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from path" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from path" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from path" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from path" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from path" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from path" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from path" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from path" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from path" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from path" -l certification-network -d 'Treats the network as a certification network'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from path" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from path" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from path" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from path" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand pki; and __fish_seen_subcommand_from path" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand network; and not __fish_seen_subcommand_from search keyserver wkd dane" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand network; and not __fish_seen_subcommand_from search keyserver wkd dane" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand network; and not __fish_seen_subcommand_from search keyserver wkd dane" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand network; and not __fish_seen_subcommand_from search keyserver wkd dane" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand network; and not __fish_seen_subcommand_from search keyserver wkd dane" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand network; and not __fish_seen_subcommand_from search keyserver wkd dane" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand network; and not __fish_seen_subcommand_from search keyserver wkd dane" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand network; and not __fish_seen_subcommand_from search keyserver wkd dane" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand network; and not __fish_seen_subcommand_from search keyserver wkd dane" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand network; and not __fish_seen_subcommand_from search keyserver wkd dane" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand network; and not __fish_seen_subcommand_from search keyserver wkd dane" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand network; and not __fish_seen_subcommand_from search keyserver wkd dane" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand network; and not __fish_seen_subcommand_from search keyserver wkd dane" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand network; and not __fish_seen_subcommand_from search keyserver wkd dane" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand network; and not __fish_seen_subcommand_from search keyserver wkd dane" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand network; and not __fish_seen_subcommand_from search keyserver wkd dane" -f -a "search" -d 'Retrieve certificates using all supported network services'
complete -c sq -n "__fish_sq_using_subcommand network; and not __fish_seen_subcommand_from search keyserver wkd dane" -f -a "keyserver" -d 'Retrieve and publishes certificates via key servers'
complete -c sq -n "__fish_sq_using_subcommand network; and not __fish_seen_subcommand_from search keyserver wkd dane" -f -a "wkd" -d 'Retrieve and publishes certificates via Web Key Directories'
complete -c sq -n "__fish_sq_using_subcommand network; and not __fish_seen_subcommand_from search keyserver wkd dane" -f -a "dane" -d 'Retrieve and publishes certificates via DANE'
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from search" -l server -d 'Set a key server to use.  Can be given multiple times.  The default can be changed in the configuration file using the setting `network.keyserver.servers`.' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from search" -l output -d 'Write to FILE (or stdout when omitted) instead of importing into the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from search" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from search" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from search" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from search" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from search" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from search" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from search" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from search" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from search" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from search" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from search" -l all -d 'Fetch updates for all known certificates'
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from search" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from search" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from search" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from search" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from search" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from keyserver" -l server -d 'Set a key server to use.  Can be given multiple times.  The default can be changed in the configuration file using the setting `network.keyserver.servers`.' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from keyserver" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from keyserver" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from keyserver" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from keyserver" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from keyserver" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from keyserver" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from keyserver" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from keyserver" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from keyserver" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from keyserver" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from keyserver" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from keyserver" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from keyserver" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from keyserver" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from keyserver" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from keyserver" -f -a "search" -d 'Retrieve certificates from key servers'
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from keyserver" -f -a "publish" -d 'Publish certificates on key servers'
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from wkd" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from wkd" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from wkd" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from wkd" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from wkd" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from wkd" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from wkd" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from wkd" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from wkd" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from wkd" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from wkd" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from wkd" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from wkd" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from wkd" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from wkd" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from wkd" -f -a "search" -d 'Retrieve certificates from a Web Key Directory'
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from wkd" -f -a "publish" -d 'Publish certificates in a Web Key Directory'
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from dane" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from dane" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from dane" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from dane" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from dane" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from dane" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from dane" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from dane" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from dane" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from dane" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from dane" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from dane" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from dane" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from dane" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from dane" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from dane" -f -a "search" -d 'Retrieve certificates using DANE'
complete -c sq -n "__fish_sq_using_subcommand network; and __fish_seen_subcommand_from dane" -f -a "generate" -d 'Generate DANE records for the given domain and certs'
complete -c sq -n "__fish_sq_using_subcommand keyring; and not __fish_seen_subcommand_from list split merge filter" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and not __fish_seen_subcommand_from list split merge filter" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and not __fish_seen_subcommand_from list split merge filter" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and not __fish_seen_subcommand_from list split merge filter" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and not __fish_seen_subcommand_from list split merge filter" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand keyring; and not __fish_seen_subcommand_from list split merge filter" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and not __fish_seen_subcommand_from list split merge filter" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and not __fish_seen_subcommand_from list split merge filter" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and not __fish_seen_subcommand_from list split merge filter" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and not __fish_seen_subcommand_from list split merge filter" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand keyring; and not __fish_seen_subcommand_from list split merge filter" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand keyring; and not __fish_seen_subcommand_from list split merge filter" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand keyring; and not __fish_seen_subcommand_from list split merge filter" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand keyring; and not __fish_seen_subcommand_from list split merge filter" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand keyring; and not __fish_seen_subcommand_from list split merge filter" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand keyring; and not __fish_seen_subcommand_from list split merge filter" -f -a "list" -d 'List keys in a keyring'
complete -c sq -n "__fish_sq_using_subcommand keyring; and not __fish_seen_subcommand_from list split merge filter" -f -a "split" -d 'Split a keyring into individual keys'
complete -c sq -n "__fish_sq_using_subcommand keyring; and not __fish_seen_subcommand_from list split merge filter" -f -a "merge" -d 'Merge keys or keyrings into a single keyring'
complete -c sq -n "__fish_sq_using_subcommand keyring; and not __fish_seen_subcommand_from list split merge filter" -f -a "filter" -d 'Join keys into a keyring applying a filter'
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from list" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from list" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from list" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from list" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from list" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from list" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from list" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from list" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from list" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from list" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from list" -l all-userids -d 'List all user ids'
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from list" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from list" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from list" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from list" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from list" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from split" -l prefix -d 'Write to files with PREFIX [defaults: `FILE-` if FILE is set, or `output-` if read from stdin]' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from split" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from split" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from split" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from split" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from split" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from split" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from split" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from split" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from split" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from split" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from split" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from split" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from split" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from split" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from split" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from merge" -l output -d 'Write to FILE or stdout if omitted' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from merge" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from merge" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from merge" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from merge" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from merge" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from merge" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from merge" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from merge" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from merge" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from merge" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from merge" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from merge" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from merge" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from merge" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from merge" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from filter" -l output -d 'Write to FILE or stdout if omitted' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from filter" -l userid -d 'Match on USERID' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from filter" -l name -d 'Match on NAME' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from filter" -l email -d 'Match on email ADDRESS' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from filter" -l domain -d 'Match on email domain FQDN' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from filter" -l cert -d 'Match on certificate fingerprints and key IDs' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from filter" -l key -d 'Match on (sub)key fingerprints and key IDs' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from filter" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from filter" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from filter" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from filter" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from filter" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from filter" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from filter" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from filter" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from filter" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from filter" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from filter" -l experimental -d 'Opt-in to using an experimental feature'
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from filter" -l prune-certs -d 'Remove certificate components not matching the filter'
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from filter" -l to-cert -d 'Convert any keys in the input to certificates.  Converting a key to a certificate removes secret key material from the key thereby turning it into a certificate.'
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from filter" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from filter" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from filter" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from filter" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand keyring; and __fish_seen_subcommand_from filter" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand packet; and not __fish_seen_subcommand_from armor dearmor dump decrypt split join" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and not __fish_seen_subcommand_from armor dearmor dump decrypt split join" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and not __fish_seen_subcommand_from armor dearmor dump decrypt split join" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and not __fish_seen_subcommand_from armor dearmor dump decrypt split join" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and not __fish_seen_subcommand_from armor dearmor dump decrypt split join" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand packet; and not __fish_seen_subcommand_from armor dearmor dump decrypt split join" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and not __fish_seen_subcommand_from armor dearmor dump decrypt split join" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and not __fish_seen_subcommand_from armor dearmor dump decrypt split join" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and not __fish_seen_subcommand_from armor dearmor dump decrypt split join" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and not __fish_seen_subcommand_from armor dearmor dump decrypt split join" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand packet; and not __fish_seen_subcommand_from armor dearmor dump decrypt split join" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand packet; and not __fish_seen_subcommand_from armor dearmor dump decrypt split join" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand packet; and not __fish_seen_subcommand_from armor dearmor dump decrypt split join" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand packet; and not __fish_seen_subcommand_from armor dearmor dump decrypt split join" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand packet; and not __fish_seen_subcommand_from armor dearmor dump decrypt split join" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand packet; and not __fish_seen_subcommand_from armor dearmor dump decrypt split join" -f -a "armor" -d 'Convert binary to ASCII'
complete -c sq -n "__fish_sq_using_subcommand packet; and not __fish_seen_subcommand_from armor dearmor dump decrypt split join" -f -a "dearmor" -d 'Convert ASCII to binary'
complete -c sq -n "__fish_sq_using_subcommand packet; and not __fish_seen_subcommand_from armor dearmor dump decrypt split join" -f -a "dump" -d 'List packets'
complete -c sq -n "__fish_sq_using_subcommand packet; and not __fish_seen_subcommand_from armor dearmor dump decrypt split join" -f -a "decrypt" -d 'Unwrap an encryption container'
complete -c sq -n "__fish_sq_using_subcommand packet; and not __fish_seen_subcommand_from armor dearmor dump decrypt split join" -f -a "split" -d 'Split a message into packets'
complete -c sq -n "__fish_sq_using_subcommand packet; and not __fish_seen_subcommand_from armor dearmor dump decrypt split join" -f -a "join" -d 'Join packets split across files'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from armor" -l output -d 'Write to FILE or stdout if omitted' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from armor" -l label -d 'Select the kind of armor header' -r -f -a "{auto\t'',message\t'',cert\t'',key\t'',sig\t'',file\t''}"
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from armor" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from armor" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from armor" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from armor" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from armor" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from armor" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from armor" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from armor" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from armor" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from armor" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from armor" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from armor" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from armor" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from armor" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from armor" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dearmor" -l output -d 'Write to FILE or stdout if omitted' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dearmor" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dearmor" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dearmor" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dearmor" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dearmor" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dearmor" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dearmor" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dearmor" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dearmor" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dearmor" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dearmor" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dearmor" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dearmor" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dearmor" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dearmor" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dump" -l cert -d 'Dump the packets of the certificate with the specified fingerprint or key ID' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dump" -l cert-userid -d 'Dump the packets of the certificate with the specified user ID' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dump" -l cert-email -d 'Dump the packets of the certificate where a user ID includes the specified email address' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dump" -l cert-file -d 'Dump the packets of the cert read from PATH' -r -F
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dump" -l output -d 'Write to FILE or stdout if omitted' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dump" -l session-key -d 'Decrypt an encrypted message using SESSION-KEY' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dump" -l recipient-file -d 'Decrypt the message using the key in KEY_FILE' -r -F
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dump" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dump" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dump" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dump" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dump" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dump" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dump" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dump" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dump" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dump" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dump" -l mpis -d 'Print cryptographic artifacts'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dump" -l hex -d 'Print a hexdump'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dump" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dump" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dump" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dump" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from dump" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from decrypt" -l output -d 'Write to FILE or stdout if omitted' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from decrypt" -l recipient-file -d 'Decrypt the message using the key in KEY_FILE' -r -F
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from decrypt" -l session-key -d 'Decrypt an encrypted message using SESSION-KEY' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from decrypt" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from decrypt" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from decrypt" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from decrypt" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from decrypt" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from decrypt" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from decrypt" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from decrypt" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from decrypt" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from decrypt" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from decrypt" -l binary -d 'Emit binary data'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from decrypt" -l dump-session-key -d 'Print the session key to stderr'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from decrypt" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from decrypt" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from decrypt" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from decrypt" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from decrypt" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from split" -l output -d 'Write to FILE or stdout if omitted' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from split" -l output-prefix -d 'Write packets to individual files starting with the given prefix.  The file names are formed by joining the prefix, the path of the packet in the source object (recall: packets can be nested), and a human-readable packet type with dashes (\'-\'). ' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from split" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from split" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from split" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from split" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from split" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from split" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from split" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from split" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from split" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from split" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from split" -l binary -d 'Emit binary data'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from split" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from split" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from split" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from split" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from split" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from join" -l output -d 'Write to FILE or stdout if omitted' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from join" -l label -d 'Select the kind of armor header' -r -f -a "{auto\t'',message\t'',cert\t'',key\t'',sig\t'',file\t''}"
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from join" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from join" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from join" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from join" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from join" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from join" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from join" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from join" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from join" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from join" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from join" -l binary -d 'Emit binary data'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from join" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from join" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from join" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from join" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand packet; and __fish_seen_subcommand_from join" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand config; and not __fish_seen_subcommand_from get inspect template" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand config; and not __fish_seen_subcommand_from get inspect template" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand config; and not __fish_seen_subcommand_from get inspect template" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand config; and not __fish_seen_subcommand_from get inspect template" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand config; and not __fish_seen_subcommand_from get inspect template" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand config; and not __fish_seen_subcommand_from get inspect template" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand config; and not __fish_seen_subcommand_from get inspect template" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand config; and not __fish_seen_subcommand_from get inspect template" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand config; and not __fish_seen_subcommand_from get inspect template" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand config; and not __fish_seen_subcommand_from get inspect template" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand config; and not __fish_seen_subcommand_from get inspect template" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand config; and not __fish_seen_subcommand_from get inspect template" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand config; and not __fish_seen_subcommand_from get inspect template" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand config; and not __fish_seen_subcommand_from get inspect template" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand config; and not __fish_seen_subcommand_from get inspect template" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand config; and not __fish_seen_subcommand_from get inspect template" -f -a "get" -d 'Get configuration options'
complete -c sq -n "__fish_sq_using_subcommand config; and not __fish_seen_subcommand_from get inspect template" -f -a "inspect" -d 'Inspect effective configuration details'
complete -c sq -n "__fish_sq_using_subcommand config; and not __fish_seen_subcommand_from get inspect template" -f -a "template" -d 'Write a template configuration file'
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from get" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from get" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from get" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from get" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from get" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from get" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from get" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from get" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from get" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from get" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from get" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from get" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from get" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from get" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from get" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from inspect" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from inspect" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from inspect" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from inspect" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from inspect" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from inspect" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from inspect" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from inspect" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from inspect" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from inspect" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from inspect" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from inspect" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from inspect" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from inspect" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from inspect" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from inspect" -f -a "paths" -d 'Inspect relevant paths'
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from inspect" -f -a "network" -d 'Inspect the network configuration'
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from inspect" -f -a "policy" -d 'Inspect the cryptographic policy'
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from template" -l output -d 'Write to FILE or stdout if omitted' -r
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from template" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from template" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from template" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from template" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from template" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from template" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from template" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from template" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from template" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from template" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from template" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from template" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from template" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from template" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand config; and __fish_seen_subcommand_from template" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand version" -l cli-version -d 'Select a CLI version' -r
complete -c sq -n "__fish_sq_using_subcommand version" -l home -d 'Set the home directory.' -r
complete -c sq -n "__fish_sq_using_subcommand version" -l key-store -d 'Override the key store server and its data' -r
complete -c sq -n "__fish_sq_using_subcommand version" -l cert-store -d 'Specify the location of the certificate store' -r
complete -c sq -n "__fish_sq_using_subcommand version" -l keyring -d 'Specify the location of a keyring to use' -r -F
complete -c sq -n "__fish_sq_using_subcommand version" -l known-notation -d 'Add NOTATION to the list of known notations' -r
complete -c sq -n "__fish_sq_using_subcommand version" -l time -d 'Set the reference time as an ISO 8601 formatted timestamp' -r
complete -c sq -n "__fish_sq_using_subcommand version" -l policy-as-of -d 'Select the cryptographic policy as of the specified time' -r
complete -c sq -n "__fish_sq_using_subcommand version" -l trust-root -d 'Consider the specified certificate to be a trust root' -r
complete -c sq -n "__fish_sq_using_subcommand version" -l password-file -d 'Seed the password cache with the specified password' -r -F
complete -c sq -n "__fish_sq_using_subcommand version" -l overwrite -d 'Overwrite existing files'
complete -c sq -n "__fish_sq_using_subcommand version" -s v -l verbose -d 'Be more verbose'
complete -c sq -n "__fish_sq_using_subcommand version" -s q -l quiet -d 'Be more quiet'
complete -c sq -n "__fish_sq_using_subcommand version" -l batch -d 'Prevents any kind of prompting'
complete -c sq -n "__fish_sq_using_subcommand version" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c sq -n "__fish_sq_using_subcommand help; and not __fish_seen_subcommand_from encrypt decrypt sign verify download inspect cert key pki network keyring packet config version help" -f -a "encrypt" -d 'Encrypt a message'
complete -c sq -n "__fish_sq_using_subcommand help; and not __fish_seen_subcommand_from encrypt decrypt sign verify download inspect cert key pki network keyring packet config version help" -f -a "decrypt" -d 'Decrypt a message'
complete -c sq -n "__fish_sq_using_subcommand help; and not __fish_seen_subcommand_from encrypt decrypt sign verify download inspect cert key pki network keyring packet config version help" -f -a "sign" -d 'Sign messages or data files'
complete -c sq -n "__fish_sq_using_subcommand help; and not __fish_seen_subcommand_from encrypt decrypt sign verify download inspect cert key pki network keyring packet config version help" -f -a "verify" -d 'Verify signed messages or detached signatures'
complete -c sq -n "__fish_sq_using_subcommand help; and not __fish_seen_subcommand_from encrypt decrypt sign verify download inspect cert key pki network keyring packet config version help" -f -a "download" -d 'Download and authenticate the data'
complete -c sq -n "__fish_sq_using_subcommand help; and not __fish_seen_subcommand_from encrypt decrypt sign verify download inspect cert key pki network keyring packet config version help" -f -a "inspect" -d 'Inspect data, like file(1)'
complete -c sq -n "__fish_sq_using_subcommand help; and not __fish_seen_subcommand_from encrypt decrypt sign verify download inspect cert key pki network keyring packet config version help" -f -a "cert" -d 'Manage certificates'
complete -c sq -n "__fish_sq_using_subcommand help; and not __fish_seen_subcommand_from encrypt decrypt sign verify download inspect cert key pki network keyring packet config version help" -f -a "key" -d 'Manage keys'
complete -c sq -n "__fish_sq_using_subcommand help; and not __fish_seen_subcommand_from encrypt decrypt sign verify download inspect cert key pki network keyring packet config version help" -f -a "pki" -d 'Authenticate certs using the Web of Trust'
complete -c sq -n "__fish_sq_using_subcommand help; and not __fish_seen_subcommand_from encrypt decrypt sign verify download inspect cert key pki network keyring packet config version help" -f -a "network" -d 'Retrieve and publish certificates over the network'
complete -c sq -n "__fish_sq_using_subcommand help; and not __fish_seen_subcommand_from encrypt decrypt sign verify download inspect cert key pki network keyring packet config version help" -f -a "keyring" -d 'Manage collections of keys or certs'
complete -c sq -n "__fish_sq_using_subcommand help; and not __fish_seen_subcommand_from encrypt decrypt sign verify download inspect cert key pki network keyring packet config version help" -f -a "packet" -d 'Low-level packet manipulation'
complete -c sq -n "__fish_sq_using_subcommand help; and not __fish_seen_subcommand_from encrypt decrypt sign verify download inspect cert key pki network keyring packet config version help" -f -a "config" -d 'Get configuration options'
complete -c sq -n "__fish_sq_using_subcommand help; and not __fish_seen_subcommand_from encrypt decrypt sign verify download inspect cert key pki network keyring packet config version help" -f -a "version" -d 'Detailed version and output version information'
complete -c sq -n "__fish_sq_using_subcommand help; and not __fish_seen_subcommand_from encrypt decrypt sign verify download inspect cert key pki network keyring packet config version help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from cert" -f -a "import" -d 'Import certificates into the local certificate store'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from cert" -f -a "export" -d 'Export certificates from the local certificate store'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from cert" -f -a "list" -d 'List all authenticated bindings (User ID and certificate pairs)'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from cert" -f -a "lint" -d 'Check certificates for issues'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from key" -f -a "list" -d 'List keys managed by the key store'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from key" -f -a "generate" -d 'Generate a new key'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from key" -f -a "import" -d 'Import keys into the key store'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from key" -f -a "export" -d 'Export keys from the key store'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from key" -f -a "delete" -d 'Delete a certificate\'s secret key material'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from key" -f -a "password" -d 'Change the password protecting secret key material'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from key" -f -a "expire" -d 'Change a certificate\'s expiration time'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from key" -f -a "revoke" -d 'Revoke a certificate'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from key" -f -a "userid" -d 'Manage User IDs'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from key" -f -a "subkey" -d 'Manage subkeys'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from key" -f -a "approvals" -d 'Manages certification approvals'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from pki" -f -a "authenticate" -d 'Authenticate a binding'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from pki" -f -a "lookup" -d 'Lookup the certificates associated with a User ID'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from pki" -f -a "identify" -d 'Identify a certificate'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from pki" -f -a "vouch" -d 'Manage certifications'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from pki" -f -a "link" -d 'Manage authenticated certificate and User ID links'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from pki" -f -a "path" -d 'Verify the specified path'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from network" -f -a "search" -d 'Retrieve certificates using all supported network services'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from network" -f -a "keyserver" -d 'Retrieve and publishes certificates via key servers'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from network" -f -a "wkd" -d 'Retrieve and publishes certificates via Web Key Directories'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from network" -f -a "dane" -d 'Retrieve and publishes certificates via DANE'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from keyring" -f -a "list" -d 'List keys in a keyring'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from keyring" -f -a "split" -d 'Split a keyring into individual keys'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from keyring" -f -a "merge" -d 'Merge keys or keyrings into a single keyring'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from keyring" -f -a "filter" -d 'Join keys into a keyring applying a filter'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from packet" -f -a "armor" -d 'Convert binary to ASCII'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from packet" -f -a "dearmor" -d 'Convert ASCII to binary'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from packet" -f -a "dump" -d 'List packets'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from packet" -f -a "decrypt" -d 'Unwrap an encryption container'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from packet" -f -a "split" -d 'Split a message into packets'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from packet" -f -a "join" -d 'Join packets split across files'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "get" -d 'Get configuration options'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "inspect" -d 'Inspect effective configuration details'
complete -c sq -n "__fish_sq_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "template" -d 'Write a template configuration file'
