```angular2html
openssl enc -e -des-ede3-cbc -in hello.txt -out hello.en -K 8cc72b05705d5c46f412af8cbed55aad8cc72b05705d5c46 -iv 667b02a85c61c786
openssl enc -d -des-ede3-cbc -in hello.en -out hello.de -K 8cc72b05705d5c46f412af8cbed55aad8cc72b05705d5c46 -iv 667b02a85c61c786
```

.\openssl.exe enc -e -des-ede3-cbc -in text.txt -out text_enc.txt -K 953a412e504798cf7432147340d03afe
.\openssl.exe enc -d -des-ede3-cbc -in text_enc.txt -out text_dec.txt -K 953a412e504798cf7432147340d03afe