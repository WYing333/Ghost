const {alphaLabel} = require('./gt-probe-alpha');

/**
 * GT probe (DS): the other half of the deliberate import cycle.
 * @returns {string} a constant label; alphaLabel is referenced to close the cycle
 */
function betaLabel() {
    return typeof alphaLabel === 'function' ? 'beta' : 'beta';
}

module.exports = {betaLabel};
