# Steganography encoder/decoder written in C

## What is setganography?
Steganography is a way to encode or hide messages/files (information) within another message or media in a concealed manner.

## How does it work?
In this program, the encoding uses a method of changing the Least Significant Bit (LSB) of the Red, Green and Blue (RGB) channel on an image. The least significant bit is the bit position in a binary integer giving the units value, usualy in the 1's position.

For example, from binary 12 (`00001100`) to binary 13 (`00001101`)

```
00001100 <-
Least significant bit
```

Changing the LSB slightly alters the color value — but this tiny change is visually undetectable to the human eye without utilizing special software. This is what makes steganography possible. For a better in-depth explination pelase watch Chris Tralie's video on a Python based steganography encoder here: https://www.youtube.com/watch?v=kkmpP_7mY_I

## Compiling
Make sure you have `gcc` or other C/C++ compiling programs installed. `gcc` can be installled on `Ubuntu` Linux by running: `sudo apt install gcc` 

Once line clone & compile.
```sh
git clone https://github.com/Roomy6/C-Steganography.git && cd C-Steganography/ && ./build.sh
```

## Usage
Using lossy image encoding such as `.jpg` will not work for decoding, it is recommended to use `.png` or `.bmp` formats instead. However, the program does support converting `.jpg` to `.png`

Running `./steg` will display the programs arguments as such:
```sh
Usage:
  Encode: ./steg encode <input_image> <output_image> <text|file> <payload>
  Decode: ./steg decode <input_image> <output_file> <text|file>
```

Example `text encoding` usage:
```sh
./steg encode inputImg.png encodedImg.png text "Hello, World!"
```

Example `binary encoding` usage:
```sh
./steg encode inputImg.png encodedImg.png file binary.exe
```

Example `text decoding` usage:
```sh
./steg decode encodedImg.png text outputText
```

Example `binary decoding` usage:
```sh
./steg decode encodedImg.png binaryOut.exe file
```

## TODO
- [ ] Binary encoding placement randomization (Based on hash?)
- [x] Text decoding outputs to file
- [x] Change data pixel brightness
- [x] Additional arguments
- [ ] Additional data encryption
- [ ] Encode file name
- [ ] Option to to encode both text and binary files

---

## Resources Used:
https://www.youtube.com/watch?v=kkmpP_7mY_I

https://solarianprogrammer.com/2019/06/10/c-programming-reading-writing-images-stb_image-libraries/

https://github.com/nothings/stb
