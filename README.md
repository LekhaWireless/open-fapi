# open-fapi
FAPI implementation for Lekha radio

Provide wireshark dissectors for analysing traffic into Lekha wireless devices.
The current implementation deviates a bit from the Small-Cell Forum's (SCF) 
definition to accomodate processor specific nuances (like cache-line size, word
alignment etc.), however eventually it would align with SCF definitions allowing
lekha devices to be controlled from other FAPI compliant wireless controllers
