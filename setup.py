#!/usr/bin/env python

from setuptools import setup

setup(name='zokrates_pycrypto',
      version='1.0',
      install_requires=[
          'bitstring==3.1.5'
      ],
      packages=['zokrates_pycrypto', 'zokrates_pycrypto.gadgets']
     )