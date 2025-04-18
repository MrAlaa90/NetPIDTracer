from setuptools import setup

setup(
    name='netpidtracer',
    version='1.0',
    description='A lightweight tool for tracing active network connections and resolving PID paths.',
    author='Alaa',
    author_email='your.email@example.com',
    py_modules=['netpidtracer_en'],
    install_requires=[
        'psutil',
        'pyfiglet',
        'tabulate',
        'wmi ; platform_system=="Windows"'
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'Operating System :: Microsoft :: Windows',
        'License :: OSI Approved :: MIT License',
    ],
    entry_points={
        'console_scripts': [
            'netpidtracer=netpidtracer_en:main'
        ]
    }
)
