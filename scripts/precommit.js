const path = require('path');
const fs = require('fs');

const map = require('../aliKey.js')

let content = fs.readFileSync(path.join(__dirname, '../ali_ddns.sh'), {
    encoding: 'utf8'
})
Object.keys(map).forEach(key => {
    content = content.replace(new RegExp(`{{${key}}}`, 'g'), map[key])
})

fs.writeFileSync(path.join(__dirname, '../ddns-start.sh'), content)
