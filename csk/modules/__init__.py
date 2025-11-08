"""
This file makes 'modules' a package and exports all
module classes for the console to discover.
"""

from .classical import (
    CaesarModule,
    AtbashModule,
    AffineModule,
    VigenereModule,
    PlayfairModule,
    RailFenceModule,
    ColumnarModule,
    MonoalphabeticModule,
    BeaufortModule,
    AutokeyModule,
    HillModule,
    ScytaleModule,
    ADFGVXModule,
    DoubleTranspositionModule
)

from .modern import (
    AESModule,
    ChaCha20Module,
    BlowfishModule,
    DESModule,
    TripleDESModule,
    TwofishModule,
    CamelliaModule,
    RC4Module,
    IDEAModule,
    RC2Module,
    RC5Module,
    RC6Module,
    SerpentModule,
    Salsa20Module
)

from .skipjack import SkipjackModule
from .gost import GOSTModule

from .asymmetric import (
    RSAModule,
    DHModule,
    ECDHModule,
    ECDSAModule,
    EdDSAModule,
    ElGamalModule,
    KyberModule,
    DilithiumModule
)

from .falcon import FalconModule
from .sphincs import SPHINCSModule
from .paillier import PaillierModule
from .bfv import BFVModule
from .ckks import CKKSModule

from .hash import (
    HashModule,
    TigerHashModule
)

from .kdf import (
    BcryptModule,
    BcryptVerifyModule,
    ScryptHashModule,
    ScryptVerifyModule,
    Argon2HashModule,
    Argon2VerifyModule,
    PBKDF2Module,
    HKDFModule
)

from .stego import (
    LSBImageHideModule,
    LSBImageRevealModule
)

from .quantum import (
    QKDModule
)

from .blockchain import (
    SimpleBlockchainModule
)

from .cryptocurrency import (
    WalletModule
)

from .lightweight import (
    AsconModule,
    PresentModule,
    SpeckModule,
    SimonModule
)

from .hybrid import (
    PGPModule
)


ALL_MODULES = [
    CaesarModule,
    AtbashModule,
    AffineModule,
    VigenereModule,
    PlayfairModule,
    RailFenceModule,
    ColumnarModule,
    MonoalphabeticModule,
    BeaufortModule,
    AutokeyModule,
    HillModule,
    ScytaleModule,
    ADFGVXModule,
    DoubleTranspositionModule,
    
    AESModule,
    ChaCha20Module,
    BlowfishModule,
    DESModule,
    TripleDESModule,
    TwofishModule,
    CamelliaModule,
    RC4Module,
    IDEAModule,
    RC2Module,
    RC5Module,
    RC6Module,
    SerpentModule,
    Salsa20Module,
    SkipjackModule,
    GOSTModule,
    
    RSAModule,
    DHModule,
    ECDHModule,
    ECDSAModule,
    EdDSAModule,
    ElGamalModule,
    KyberModule,
    DilithiumModule,
    FalconModule,
    SPHINCSModule,
    PaillierModule,
    BFVModule,
    CKKSModule,
    
    HashModule,
    TigerHashModule,
    
    BcryptModule,
    BcryptVerifyModule,
    ScryptHashModule,
    ScryptVerifyModule,
    Argon2HashModule,
    Argon2VerifyModule,
    PBKDF2Module,
    HKDFModule,
    
    LSBImageHideModule,
    LSBImageRevealModule,

    QKDModule,

    SimpleBlockchainModule,

    WalletModule,

    AsconModule,
    PresentModule,
    SpeckModule,
    SimonModule,

    PGPModule,
]