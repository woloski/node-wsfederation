var xml2js = require('xml2js');

WsFederation.prototype = {
  getIdentityProviderSelectorUri: function (namespace, wtrealm, whr) {
    if (whr !== '')
    {
      return "https://" + namespace + ".accesscontrol.windows.net/v2/wsfederation/?wtrealm=" + wtrealm + "&wa=wsignin1.0&whr=" + whr;   
    }
    else
    {
      return "https://" + namespace + ".accesscontrol.windows.net/v2/wsfederation/?wtrealm=" + wtrealm + "&wa=wsignin1.0";
    } 
  },

  getToken: function(res) {
    var parser = new xml2js.Parser();
    parser.on('end', function(result) {
      var str = result['t:RequestedSecurityToken']['wsse:BinarySecurityToken']['#'];
      var result = new Buffer(str, 'base64').toString('ascii');
      return result;
    });

    parser.parseString(res.req.body['wresult']);
  })
};