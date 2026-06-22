const { exec } = require('child_process');

function run(cmd) {
    // CWE-78: OS Command Injection
    exec(cmd);
}

const express = require('express');
const app = express();

app.get('/user', (req, res) => {
    // CWE-95: Eval with expression
    eval(req.query.q);
});
