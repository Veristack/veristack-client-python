"""Package setup."""
from setuptools import find_packages
from setuptools import setup


with open('requirements.txt') as f:
    REQUIRED = f.read().splitlines()

REQUIRED = [r for r in REQUIRED if not r.startswith('git')]


setup(
    name='veristack-client',
    version='0.1',
    install_requires=REQUIRED,
    description='A client for interfacing to Veristack',
    author='Clifton Barnes',
    author_email='cbarnes@veristack.com',
    url='https://veristack.com/',
    platforms='OS Independent',
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Plugins',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries'
    ]
)
