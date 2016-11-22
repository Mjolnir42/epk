# epk, Encrypted Private Key

```
package epk // import "github.com/mjolnir42/epk"

Package epk implements an encrypted private key on top of the Ed25519
signature scheme. Given the passphrase and a message it can also unlock the
key and sign the message.

It uses scrypt as key derivation function and ChaCha20/Poly1305 for
encryption.

type EncryptedPrivateKey struct { ... }
    func New(passphrase string) (*EncryptedPrivateKey, ed25519.PublicKey, error)


func New(passphrase string) (*EncryptedPrivateKey, ed25519.PublicKey, error)
    New returns the plain public and encrypted private key for a generated
    keypair.


func ReadFrom(r io.Reader) (*EncryptedPrivateKey, error)
    ReadFrom reconstructs EncryptedPrivateKey from line data read in from r.
    Comment lines starting with a '#' as well as lines that are empty or only
    contain whitespace are skipped. The first non-skipped line is expected to be
    the output of Armor() on a single line, surrounding whitespace is ignored.
    Additional lines are ignored.

    ReadFrom returns io.ErrUnexpectedEOF if no data line could be found as well
    as any error that occurred.


func (e *EncryptedPrivateKey) Armor() (string, error)
    Armor returns the ascii armored binary serialization of e. The ASCII armor
    is encoded using standard base64.


func (e *EncryptedPrivateKey) Sign(passphrase string, message []byte) ([]byte, error)
    Sign signs the message with the private key protected by passphrase and
    returns the signature.
```
