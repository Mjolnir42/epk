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


func (e *EncryptedPrivateKey) Armor() (string, error)
    Armor returns the ascii armored binary serialization of e. The ASCII armor
    is encoded using standard base64.

func (e *EncryptedPrivateKey) Sign(passphrase string, message []byte) ([]byte, error)
    Sign signs the message with the private key protected by passphrase and
    returns the signature.
```
