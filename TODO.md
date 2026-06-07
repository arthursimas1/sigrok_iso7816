* increase code coverage
* design how to sync the decoding when the data capture does not start at the beginning of a byte transmission
* design how to handle cases where ATR is not present in the beginning of the stream
    * not present at all: guess all parameters
    * present but later on the message stream: can buffer the first readings until the first ATR is read
