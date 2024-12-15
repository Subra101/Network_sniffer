from setuptools import setup

setup(
    name='NetSniffer',
    version='1.0',
    packages=['netsniffer'],
    install_requires=[
        'scapy',
        'pyshark',
        'sqlite3',
        'matplotlib',
        'seaborn'
    ],
    author='HackerGPT',
    author_email='hacker@gpt.com',
    description='A network traffic analyzer tool',
    url='https://github.com/HackerGPT/NetSniffer',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent'
    ],
    entry_points={
        'console_scripts': [
            'netsniffer=netsniffer:main'
        ]
    }
)