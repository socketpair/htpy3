# coding: utf-8
from setuptools import setup, Extension
from Cython.Build import cythonize

setup(
    name='htpy3',
    version='1.0.0',
    author='Коренберг Марк',
    author_email='socketpair@gmail.com',
    description='cython htpy binding',
    license='TBD',
    keywords = "libhtp cython htpy",
    ext_modules = cythonize([
        Extension(
            "htpy3/main",
            ["htpy3/main.pyx"],
            libraries=["htp"]
        )
    ]),
    packages=['htpy3'],
)
