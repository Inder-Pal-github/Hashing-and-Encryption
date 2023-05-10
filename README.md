

# Hashing vs Encryption

- **Hashing**
    
    **Hashing is a one-way process that takes input data and produces a fixed-size string of characters, called a hash.**
    
     The ***hash is unique to the input data***, which means that any changes to the input data will result in a different hash. 
    
    Hashing is commonly used for *password storag*e and *data integrity checks*. When you create an account on a website, the password you create is not stored as plain text. Instead, the website hashes your password and stores the hash. When you try to log in, the website hashes the password you entered and compares it to the hash that was stored. If the hashes match, you are granted access.
    
- **************Example**************
    
    ```
    // Using bcrypt library for hashing password
    import bcrypt
    
    # Generate a salt for the password hash
    salt = bcrypt.gensalt()
    
    # Hash the password with the salt
    password = "password123"
    hashed_password = bcrypt.hashpw(password, salt)
    
    # Check if a password matches a hash
    password_attempt = "password123"
    if bcrypt.checkpw(password_attempt, hashed_password):
        print("Password is correct!")
    else:
        print("Password is incorrect.")
    
    ```
    
- **Encryption**
    
    **Encryption, on the other hand, is a two-way process that takes input data and transforms it into an unreadable form, called ciphertext.** 
    
    The original data can only be retrieved by using a decryption key. Encryption is commonly used to protect sensitive data during transmission or storage. For example, when you access a website with a secure connection (HTTPS), the data that is sent between your device and the website is encrypted to prevent anyone from intercepting and reading the data.
    
    - Encryption is the process of encoding simple text and other information that can be accessed by the sole authorized entity if it has a decryption key. It will protect your sensitive data from being accessed by cybercriminals. It is the most effective way of achieving [data security](https://www.ssl2buy.com/wiki/transmit-data-securely-with-ssl-encryption/) in modern communication systems. In order for the receiver to read an encrypted message, he/she should have a password or a security key that is used in decryption. Data that has not been encrypted is known as plain text while encrypting data is known as a cipher text.  There are a number of encryption systems, where an asymmetric encryption is also known as public-key encryption, symmetric encryption and hybrid encryption are the most common.
    - **[Symmetric encryption](https://www.notion.so/Hashing-vs-Encryption-503773a8935544b28175939caf13914e) –** Uses the same secret key to encrypt and decrypt the message. The secret key can be a word, a number or a string of random letters. Both the sender and the receiver should have the key. It is the oldest technique of encryption.
        
        ![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/cca3758f-68b4-4b31-886d-ce9b9158a15c/Untitled.png)
        
    - **Asymmetric encryption –** It deploys two keys, [a public key known by everyone and a private key known only by the receiver](https://www.notion.so/Hashing-vs-Encryption-503773a8935544b28175939caf13914e). The public key is used to encrypt the message and a private key is used to decrypt it. Asymmetric encryption is little slower than symmetric encryption and consumes more processing power when encrypting data.
        
        ![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/80e94d20-0144-4f22-9259-8d319cd99ee9/Untitled.png)
        
    
    - **Hybrid encryption –** It is a process of encryption that blends both symmetric and asymmetric encryption. It takes advantage of the strengths of the two encryptions and minimizes their weakness.
        - ****What is a Public and Private Key Pair?****
            
            ### **Public and Private key pair helps to encrypt information that ensures data is protected during transmission.**
            
            Private Key and public key are a part of encryption that encodes the information. Both keys work in two encryption systems called [symmetric and asymmetric](https://www.ssl2buy.com/wiki/symmetric-vs-asymmetric-encryption-what-are-differences). Symmetric encryption (private-key encryption or secret-key encryption) utilize the same key for [encryption and decryption](https://www.ssl2buy.com/wiki/what-is-encryption-and-decryption). Asymmetric encryption utilizes a pair of keys like public and private key for better security where a message sender encrypts the message with the public key and the receiver decrypts it with his/her private key.
            
            Public and Private key pair helps to encrypt information that ensures data is protected during transmission.
            
            ![https://www.ssl2buy.com/wp-content/uploads/2014/12/Public-and-Private-Key-SSL-Encryption.png](https://www.ssl2buy.com/wp-content/uploads/2014/12/Public-and-Private-Key-SSL-Encryption.png)
            
            # **Public Key**
            
            Public key uses asymmetric algorithms that convert messages into an unreadable format. A person who has a public key can encrypt the message intended for a specific receiver. The receiver with the private key can only decode the message, which is encrypted by the public key. The key is available via the public accessible directory.
            
            # **Private Key**
            
            The private key is a secret key that is used to decrypt the message and the party knows it that exchange message. In the traditional method, a secret key is shared within communicators to enable encryption and decryption the message, but if the key is lost, the system becomes void. To avoid this weakness, PKI ([public key infrastructure](http://en.wikipedia.org/wiki/Public_key_infrastructure)) came into force where a public key is used along with the private key. PKI enables internet users to exchange information in a secure way with the use of a public and private key.
            
            # **Key Size and Algorithms**
            
            There are RSA, DSA, ECC ([Elliptic Curve Cryptography](https://www.ssl2buy.com/wiki/ecc-algorithm-to-enhance-security-with-better-key-strength)) algorithms that are used to create a public and private key in public key cryptography (Asymmetric encryption). Due to security reason, the latest [CA/Browser forum](https://cabforum.org/) and IST advises to use 2048-bit RSA key. The key size (bit-length) of a public and private key pair decides how easily the key can be exploited with a [brute force attack](https://www.ssl2buy.com/wiki/brute-force-attack). The more computing power increases, it requires more strong keys to secure transmitting data.
            
        
        The `crypto` module in Node.js provides a way to encrypt and decrypt messages using various algorithms. The example code above uses the `aes-256-cbc` algorithm, which is a symmetric encryption algorithm that uses the same key for both encryption and decryption. The `encrypt` function takes in a plaintext message and returns an object containing the initialization vector (IV) and the encrypted message. The `decrypt` function takes in the encrypted message object and returns the decrypted plaintext message.
        
        ### **Difference Between Symmetric and Asymmetric Encryption**
        
        - Symmetric encryption uses a single key that needs to be shared among the people who need to receive the message while asymmetric encryption uses a pair of public key and a private key to encrypt and decrypt messages when communicating.
        - Symmetric encryption is an old technique while asymmetric encryption is relatively new.
        - Asymmetric encryption was introduced to complement the inherent problem of the need to share the key in symmetric encryption model, eliminating the need to share the key by using a pair of public-private keys.
        - Asymmetric encryption takes relatively more time than the symmetric encryption.
        
        | Key Differences | Symmetric Encryption | Asymmetric Encryption |
        | --- | --- | --- |
        | Size of cipher text | Smaller cipher text compares to original plain text file. | Larger cipher text compares to original plain text file. |
        | Data size | Used to transmit big data. | Used to transmit small data. |
        | Resource Utilization | Symmetric key encryption works on low usage of resources. | Asymmetric encryption requires high consumption of resources. |
        | Key Lengths | 128 or 256-bit key size. | RSA 2048-bit or higher key size. |
        | Security | Less secured due to use a single key for encryption. | Much safer as two keys are involved in encryption and decryption. |
        | Number of keys | Symmetric Encryption uses a single key for encryption and decryption. | Asymmetric Encryption uses two keys for encryption and decryption |
        | Techniques | It is an old technique. | It is a modern encryption technique. |
        | Confidentiality | A single key for encryption and decryption has chances of key compromised. | Two keys separately made for encryption and decryption that removes the need to share a key. |
        | Speed | Symmetric encryption is fast technique | Asymmetric encryption is slower in terms of speed. |
        | Algorithms | RC4, AES, DES, 3DES, and QUAD. | RSA, Diffie-Hellman, ECC algorithms. |
- **Example : Symmetric encryption/decryption**
    
    ```
    const crypto = require('crypto');
    
    // Encryption
    const algorithm = 'aes-256-cbc';
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    
    function encrypt(text) {
      let cipher = crypto.createCipheriv(algorithm, Buffer.from(key), iv);
      let encrypted = cipher.update(text);
      encrypted = Buffer.concat([encrypted, cipher.final()]);
      return { iv: iv.toString('hex'), encryptedData: encrypted.toString('hex') };
    }
    
    // Decryption
    function decrypt(text) {
      let iv = Buffer.from(text.iv, 'hex');
      let encryptedText = Buffer.from(text.encryptedData, 'hex');
      let decipher = crypto.createDecipheriv(algorithm, Buffer.from(key), iv);
      let decrypted = decipher.update(encryptedText);
      decrypted = Buffer.concat([decrypted, decipher.final()]);
      return decrypted.toString();
    }
    
    // Example usage
    let message = "This is a secret message";
    let encryptedMessage = encrypt(message);
    let decryptedMessage = decrypt(encryptedMessage);
    
    console.log("Original message:", message);
    console.log("Encrypted message:", encryptedMessage);
    console.log("Decrypted message:", decryptedMessage);
    
    ```
    
- **Conclusion**
    - **Difference between Hashing and Encryption**
        
        The data that has been hashed into an unreadable string cannot be converted back into a readable string, whereas in encryption, with the use of cryptographic keys, the encrypted data may be decoded and turned into a string of readable letters (plaintext information).
        
        The length of the illegible characters is fixed in hashing but there is no set length for the illegible characters in encryption.
        
        In hashing, keys are not used but keys are used to encrypt information in encryption. Only public keys are used for symmetric encryption. Both public and private keys are utilised in asymmetric encryption.
        
        ![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/8c4258d2-0ce4-4d7d-8a89-aa7bf88834f6/Untitled.png)
        
    
    While both hashing and encryption are methods of data security, they serve different purposes. Hashing is used to ensure data integrity and password storage, while encryption is used to protect data confidentiality. It's important to understand the differences between these two methods so that you can choose the right one for your specific security needs.
    
    For hashing passwords, the popular bcrypt library can be used in many programming languages.
    

[Further reading](https://www.notion.so/Further-reading-69b59fd507e04cbd88d848db33df8bd0)
