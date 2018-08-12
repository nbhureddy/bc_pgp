# bc_pgp

Steps to create Public & Private key using GNUPG

  1. brew install gpg
  2. Generate a key
  
    gpg2 --full-generate-key  //for a full featured key generation dialog
          OR
    gpg --gen-key   //It asks for passphrase - remember the passphrase
        
  3. Export Public Key
  
    gpg --export --armor <email_id>  > mypubkey.asc
    
  4. Export Secret Key
  
    gpg --export-secret-keys -a 9B3B502F736E67C3835C87CCCBEC5EB71D82E86D > myprivatekey.asc
      
        The ID in the above command can be extracted from
        
            gpg --list-keys

Other useful gpg commands

   Every time a KEY is generated using command line tool - a new key gets added to the public key ring. The list is present in $USERHOME/.gpg/ directory

   To clean the 
   
      gpg --delete-secret-keys <userName>   // <userName> can be extracted from `gpg --list-keys` command
      gpg --delete-key <userName>


Encryption & decryption on Terminal

    gpg --import mypubkey.asc 
    echo "123456789" | gpg --encrypt --armor -r 1BBA274C216FF472 | base64 >> xyz.txt.pgp
    cat xyz.txt.pgp | base64  --decode | gpg —decrypt


If you face -gpg: public key decryption failed: Inappropriate ioctl for device
 do :  export GPG_TTY=$(tty)
