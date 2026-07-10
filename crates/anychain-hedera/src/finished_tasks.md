1.
I noticed that you're submitting the AccountCreation transaction with Hedera's offical
execute(), which means you've deserialized our stream again. I don't need etiher the deserizalization
or the offical execute() method to for submission. What I need is you generate the final
stream and submit it over gPRC just as you do with the balance transfer transaction.

Furthermore, the test seems to failed with an insufficent balance error. I need you to
complete a successful account creation and a successful balance transfer. If requesting
some HBAR from the faucet is necessary, you may do so.