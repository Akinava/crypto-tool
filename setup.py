from setuptools import setup, find_packages


setup(
    name='crypto-tool',
    description='cryptography tools',
    url='https://github.com/Akinava/crypto-tool',
    version='0.0.0',
    packages=find_packages(),
    python_requires='>=3.6, <4',
    install_requires=[
        'pycryptodome==3.10.1',
        'ecdsa==0.16.1',
        'tinyec==0.3.1',
    ],
)
