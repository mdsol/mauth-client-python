import re
import subprocess
from setuptools import setup, find_packages

NAME = 'mauth_client'
VERSION = re.search("__version__ = '([^']+)'", open(NAME + '/__init__.py').read()).group(1)

INSTALL_REQUIRES = ['cachetools', 'requests', 'rsa']


setup(
    name=NAME,
    version=VERSION,
    url='https://github.com/mdsol/mauth-client-python',
    author='Medidata Solutions',
    author_email='support@mdsol.com',
    license='MIT',
    description="MAuth Client for Python",
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    packages=find_packages(exclude=["tests"]),
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    install_requires=INSTALL_REQUIRES,
    tests_require=['boto3',
                   'flask',
                   'freezegun',
                   'python-dateutil<2.7.0,>=2.1', # botocore requires python-dateutil < 2.7.0
                   'requests-mock'],
    test_suite='tests'
)
