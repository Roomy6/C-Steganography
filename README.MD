A super simple steganography program made in the C programming language.
## What is setganography?
Steganography is a way to encode or hide messages/files (information) within another message or media in a concealed manner.

## How does it work?
In this program, the encoding uses a method of changing the Least Significant Bit (LSB) of the Red, Green and Blue (RGB) channel on an image. The least significant bit is the bit position in a binary integer giving the units value, usualy in the 1's position.

For example the number 12 in binary would be: `00001100`
Changing the LSB of 12 would turn it to 13: `00001101`

```
00001100
	   ^
	   Least significant bit
```

Changing the LSB slightly alters the color value — for example, from 12 (`00001100`) to 13 (`00001101`) — but this tiny change is visually undetectable to the human eye without utilizing special software. This is what makes steganography possible.

## Compiling
Make sure you have `gcc` or other C/C++ compiling programs installed. `gcc` can be installled on `Ubuntu` Linux by running: `sudo apt install gcc` 

Clone the GitHub repo project.
`git clone` 
Compile the project to a binary file called `steg`
`gcc main.c image.c stego.c -o steg -lm` 

## Usage
Using lossy image encoding such as `.jpg` will not work for decoding, it is recommended to use `.png` or `.bmp` formats instead. However, the program does support converting `.jpg` to `.png`

Running `./steg` will display the programs arguments as such:
```
Usage:
  Encode: ./steg encode <input_image> <output_image> <text|file> <payload>
  Decode: ./steg decode <input_image> <output_file> <text|file>
```

Example `text encoding` usage:
```
./steg encode inputImg.png encodedImg.png text "Hello, World!"
```

Example `binary encoding` usage:
```
./steg encode inputImg.png encodedImg.png file binary.exe
```

Example `text decoding` usage:
```
./steg decode encodedImg.png text outputText
```

Example `binary decoding` usage:
```
./steg decode encodedImg.png binaryOut.exe file
```

---
## Resources Used:
https://www.youtube.com/watch?v=kkmpP_7mY_I

https://solarianprogrammer.com/2019/06/10/c-programming-reading-writing-images-stb_image-libraries/

https://github.com/nothings/stb