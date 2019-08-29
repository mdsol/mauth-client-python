import re
import subprocess
from setuptools import setup, find_packages

NAME = 'mauth_client'
VERSION = re.search("__version__ = '([^']+)'", open(f'{NAME}/__init__.py').read()).group(1)
INSTALL_REQUIRES = ['requests-mauth']


setup(
    name=NAME,
    version=VERSION,
    url='https://github.com/mdsol/mauth-client-python',
    author='Yohei Kitamura',
    author_email='ykitamura@mdsol.com',
    description="MAuth Client for Python",
    long_description=open('README.md').read(),
    packages=find_packages(exclude=["tests"]),
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7'
    ],
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    install_requires=INSTALL_REQUIRES,
    tests_require=['boto3',
                   'cachetools',
                   'six',
                   'freezegun',
                   'python-dateutil<2.7.0,>=2.1', # botocore requires python-dateutil < 2.7.0
                   'requests-mock'],
    test_suite='tests'
)
