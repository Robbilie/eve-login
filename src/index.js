"use strict";
module.exports = new Proxy({}, { get: (P,key) => {
    if (key === Symbol.iterator)
        return () => require("fs")
            .readdirSync(__dirname)
            .filter(x => !x.startsWith("index") && !x.includes(".test.") && x.split(".").slice(-1)[0].includes("js"))
            .map(x => require(`./${x}`))[Symbol.iterator]();
    else
        return require(`./${key}`);
}});
