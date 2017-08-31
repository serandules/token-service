var pot = require('pot');

before(function (done) {
    console.log('starting up the server');
    pot.start(done);
});

after(function (done) {
    console.log('shutting down the server');
    pot.stop(done);
});