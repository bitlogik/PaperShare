#!/usr/bin/python2
# -*- coding: ascii -*-

# PaperShare
# Copyright (C) 2018  Antoine FERRON - BitLogiK

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>


import os
import sys
import random
import hashlib
from chacha import *
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.image as mpimg
from matplotlib.widgets import Slider, Button

def gen_random():
    # return 256 random bits
    # First get 384 random bytes from the OS
    random_from_os = bytes(os.urandom(384))
    assert random_from_os.__len__() == 384
    rnd_list = []
    for x in range(12):
        rnd_list.append(random_from_os[32*x:32*(x+1)])
    # Get 8 random chunks out of the 12
    sel_random = random.SystemRandom().sample(rnd_list, 8)
    # get 256 bits from 256 random-source bytes
    return hashlib.sha256("".join(sel_random)).digest()

def char2bin(a):
    # convert a uint8 char in binary -ASCII string
    s = ''
    t = { '0':'\0\0\0','1':'\0\0\1','2':'\0\1\0','3':'\0\1\1',
          '4':'\1\0\0','5':'\1\0\1','6':'\1\1\0','7':'\1\1\1'  }
    for c in oct(a)[1:]:
        s += t[c]
    if len(s) == 9:
        s = s[1:]
    while(len(s)<8):
        s = '\0' + s
    return s

def string2bin(cstr):
    # convert a string to a binary
    s = ''
    for x in cstr:
        s += char2bin(x)
    return s

def flat2array(binstr):
    # convert HeightxWidth list in to a table
    return np.fromstring(binstr, np.uint8) \
                .reshape((HEIGHT, WIDTH))

def bin2img(binarray):
    # convert the table with the XOR graphical pattern
    xorform = np.array(
            [ [0, 0, 1, 1],
              [0, 0, 1, 1],
              [1, 1, 0, 0],
              [1, 1, 0, 0] ]
        )
    symb_list = []
    img_lines = []
    for b in np.nditer(binarray):
        symb_list.append( xorform ^ b )
    for line in range(HEIGHT):
        line_idx = line * WIDTH
        img_lines.append(np.concatenate(
                            symb_list[line_idx : line_idx+WIDTH],
                            1 )
                        )
    return np.vstack(img_lines)

def update_draw_imgs(evt):
    # compute and redraw when BWthreshold changes
    global ciphered_img
    # Image filter to black or white
    msg_array = np.where(img_inputgray > threshold_slider.val,
                          0,
                          1)
     # Encryption of the data and image generation
    ciphered_img = bin2img(ks_array ^ msg_array)
    img_plot.set_data(msg_array)
    cim_plot.set_data(ciphered_img)

if __name__ == "__main__":
    
    # Load png image file
    if len(sys.argv) < 2:
        filename = 'input.png'
    else:
        filename = sys.argv[1]
    print filename
    img_input = mpimg.imread(filename)
    
    # Fast conversion to grayscale 0.3R 0.6G 0.1B
    img_inputgray = (   0.3 * img_input[:,:,0]
                      + 0.6 * img_input[:,:,1]
                      + 0.1 * img_input[:,:,2] )
    print "Image Loaded :"
    print img_inputgray.shape, img_inputgray.dtype
    
    # Image properties loading and checks
    WIDTH  = img_inputgray.shape[1]
    HEIGHT = img_inputgray.shape[0]
    if WIDTH > 200 or HEIGHT > 200:
        raise Exception("Width and Height over 200 pixels aren't"
                "recommended\nPlease resize input.png")
    tot_lenght = WIDTH * HEIGHT
    if tot_lenght % 8 != 0:
        raise Exception("Width x Height must be a multiple of 8")
    
    # Image filter to black or white
    BWthresDft = 0.5
    img_array = np.where(img_inputgray > BWthresDft, 0, 1)
    
    # Key stream generation (Pseudo Random from chacha20)
    iv = 8*"\0"
    ctx = init_state(iv, gen_random())
    ks = gen_keystream(ctx, tot_lenght/8)
    ks_array = flat2array(string2bin(ks))
    
    # Encryption of the data
    ciphered_array = ks_array ^ img_array
    
    # generating output images
    ks_print = bin2img(ks_array)
    ciphered_img = bin2img(ciphered_array)
    
    # Display image result in a window
    fig = plt.figure(0)
    fig.canvas.set_window_title('PaperShare image setup')
    fig.set_size_inches(12,6)
    plt.subplot(121)
    plt.subplots_adjust(bottom = 0.2)
    img_plot = plt.imshow(img_array, cmap='gray_r')
    ThAxes = plt.axes( [0.15, 0.08, 0.4, 0.015] ,
                            facecolor='#ccf2ff')
    threshold_slider = Slider(ThAxes,'B/W threshold',
                              0.0, 1.0, valinit=BWthresDft, color='#121254')
    threshold_slider.on_changed(update_draw_imgs)
    axbut = plt.axes([0.75, 0.04, 0.08, 0.07])
    bok = Button(axbut, 'OK')
    bok.label.set_fontsize(14)
    bok.on_clicked(fig.canvas.manager.destroy)
    plt.subplot(122)
    cim_plot = plt.imshow(ciphered_img, cmap='gray')
    plt.show()
    
    # Save to png files
    mpimg.imsave('KeypadMask.png', np.flipud(ks_print), cmap='gray')
    mpimg.imsave('ImageMask.png', ciphered_img, cmap='gray')
    
    print "\nPaper secret sharing generation finished :)"
    raw_input("PRESS ENTER to continue")

