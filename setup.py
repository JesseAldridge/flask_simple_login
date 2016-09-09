
from setuptools import setup, find_packages
import sys, os

version = '0.0.1'

setup(name='flask-simple-login',
      version=version,
      description="Easily turn your python data into a flot graph in a static html file.",
      long_description="""""",
      classifiers=[],
      keywords='flask auth login',
      author='Jesse Aldridge',
      author_email='JesseAldridge@gmail.com',
      url='https://github.com/JesseAldridge/flask_simple_login',
      license='MIT',
      packages=['flask_simple_login'],
      include_package_data=True,
      zip_safe=True,
      install_requires=[
          # -*- Extra requirements: -*-
      ]
      )

