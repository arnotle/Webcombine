const express = require('express');
const router = express.Router();

const machines = [
    { name: 'Machine 1' },
    { name: 'Machine 2' },
    { name: 'Machine 3' }
];

router.get('/add', (req, res) => {
    res.render('add', { machines });
});

module.exports = router;
