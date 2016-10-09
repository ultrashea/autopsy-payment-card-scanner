# autopsy-payment-card-scanner
Autopsy module for finding and Luhn checksum validating payment card (credit cards, debit cards, etc) numbers during a forensic investigation.

This Autopsy module will search for possible payment card numbers, and will then check the Luhn checksum of each possible payment card number, which will provide a greater degree of confidence regarding if a numeric sequence is a payment card number or not.

(Note: A successful Luhn checksum validation does not guarantee that a payment card number is in use by a payment card vendor, just that it is potentially valid.  A numeric sequence that does not pass Luhn checksum validation can be assumed to not be a valid payment card number)

Usage: Move the Payment_Card_Scanning_Module.py into the Autopsy Python Module directory, and enable the "Payment Card Scanning Module" ingest module.  Files with Luhn validated payment card numbers will be reported in the Interesting Items section under the heading "Files With Possible Payment Card Numbers".  By default, the module does not scan binary files - scanning of binary files can be enabled by setting the self.skipBinaries variable in the module to 0.