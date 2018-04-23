
# PaperShare

A visual encryption scheme to hide images. Images are encrypted in 2 images. The 2 images are required to read the original image.
This is based on visual cryptography by Naor and Shamir. ([Read the paper](https://www.fe.infn.it/u/filimanto/scienza/webkrypto/visualdecryption.pdf))


## Installation

Requirements :

 - Python v2.7 ( [install](https://www.python.org/downloads/release/python-2714/) )
 - NumPy      ( [install](https://pypi.org/project/numpy/) )
 - Matplotlib v2 ( [install](https://matplotlib.org/users/installing.html) )

From a CLI with python 2 :

    python -mpip install -U numpy
    python -mpip install -U matplotlib

In case of any issue with pip, try with your package manager or get binaries for windows.


## Using PaperShare

### Generate the 2 images

Resize any image you want to encode to the following :

 - PNG format, without transparency *
 - Height and Width < 200 pixels
 - Height &#215; Width is a multiple of 8

Give this image file in argument to the PaperShare command :
`papershare.py path/img.png`

Or replace the given *input.png* image in the PaperShare directory :
`papershare.py`

Select the gray-scale limit you like using '*B/W threshold*' slider at the bottom of the window.
Click "*OK*" button when ready. 

PaperShare is outputting 2 images files :

 - KeypadMask.png &#8592; the key stream mask 
 - ImageMask.png  &#8592; the encrypted image

One of the 2 images can be public and the other one private. This way, you will have only one paper to keep yourself. Still, to even improve security you can keep both private. Also with one part public, there is no improvement over a single secret paper.

\* Full transparency zones will be black, so make all pixels a color or get rid of the alpha channel.


### Print the images

You can print the images using your operating system print wizard. Images can be printed on the same paper face, one image above the other. They can be printed on 2 different sheets. Obviously, print on 2 different printers is even more secured, but printing with the exact same size might be quite harder.

One main requirement is that **the 2 images needs to be the exact same size** (length difference < 0.2 mm).

We recommend to print images with **at least 10 cm width for a 160 pixels** original image.


### Visual decryption

If you printed on the same sheet face, one image above the other, simply fold the paper between the 2 images and superpose the 2 images with the ink inside (in the middle of the 2 pages).
Anyway, the 2 images has to be **superposed with the ink facing to the other**. The blank part of the sheets at the outside.
Our tests shown this type of printing/reading greatly improve the readability. Because the ink are nearly on the same plane, their shade perception is equal.

Press firmly the 2 sheets on a **bright source of light** such as :

 - A window glass during a sunny day
 - A lamp-shape light bulb during night
 - An overhead projector
 - A lighted view box  ( for xray )

The remaining air layer between the 2 paper sheets is the main disturbing thing when decoding a papershare. So be careful to push on paper everywhere to remove air inside.

An easy technique to accurately align the 2 images is :

- carefully align a corner at first
- pinch this corner with your nail, making it a pivot point
- rotate the sheet around this corner to align the rest


### Reconstruction with a computer

Just vertically flip (mirror) the keymask image. Then with an image preview software, when you change the image (next / using right arrow), the image will briefly "flash" during the image change. Changing back and forth quickly between the 2 images and you should perceive the original image.

To better verify using an image editor software that the images generated are rightly generated :

 - open the 2 images in one image on 2 different layers
 - vertically flip the KeypadMask layer
 - Select "darken" blending mode for the top layer

That is simulating what you would see when superposing papers. To get a clear fully decoded data image, select instead "difference" (or even "xor") blending mode and invert (negative) the result.


## Technical details and Security

PaperShare is based on the [chacha20](https://cr.yp.to/chacha/chacha-20080128.pdf) stream cipher, standardized by [RFC7539](https://tools.ietf.org/html/rfc7539). Chacha20 is an improvement of the [Salsa20 stream cipher](https://cr.yp.to/snuffle/spec.pdf). The scheme is mathematically secure as this is a one-time pad ciphering.

Chacha20 is used to generate a key stream (the one-time pad), from a random source. The full stream pad is kept, and not the initial state key as usually done. Chacha20 is expanding a 256 bits random secret into a stream, which is used to XOR the image. This is as secured as the Chacha20 implementation provided.

- one image (*KeypadMask.png*) is the key stream.
- the other image (*ImageMask.png*) is the encrypted image.

> encrypted_image = key_stream &#8853; original_image

The decryption is visually automatic, as a xor pattern allows to mimic a mathematical xor with the two images superposed. Actually, 1 is middle-tone grey and 0 is black.

> original_image = key_stream &#8853; encrypted_image

The key stream pad or the encrypted image can be publicly shared, and the other one remains secret. This won't disclose any information to an attacker/watcher. Both images are required to decrypt the information. Still, the interest of this method is to store both images in different places so that only when combined the secret is read. Also it can be used to transmit the keypad on a side channel, relatively secure, and the encrypted image on a main channel, insecure.


## License

Copyright (C) 2018  Antoine FERRON - BitLogiK

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 3 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

