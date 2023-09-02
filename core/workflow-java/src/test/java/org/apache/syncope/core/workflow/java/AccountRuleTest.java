package org.apache.syncope.core.workflow.java;

import org.apache.syncope.common.lib.policy.AbstractAccountRuleConf;
import org.apache.syncope.common.lib.policy.DefaultAccountRuleConf;
import org.apache.syncope.core.persistence.api.entity.PlainAttrUniqueValue;
import org.apache.syncope.core.persistence.api.entity.user.UPlainAttr;
import org.apache.syncope.core.persistence.api.entity.user.User;
import org.apache.syncope.core.persistence.jpa.entity.JPAPlainSchema;
import org.apache.syncope.core.persistence.jpa.entity.user.JPAUPlainAttr;
import org.apache.syncope.core.persistence.jpa.entity.user.JPAUPlainAttrUniqueValue;
import org.apache.syncope.core.persistence.jpa.entity.user.JPAUser;
import org.apache.syncope.core.spring.policy.AccountPolicyException;
import org.apache.syncope.core.spring.policy.DefaultAccountRule;
import org.hamcrest.CoreMatchers;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.regex.PatternSyntaxException;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.junit.Assert.*;

@RunWith(value= Parameterized.class)
public class AccountRuleTest {
    final static String validRegex = "^[a-zA-Z0-9_]+$";
    final static String notValidRegex = "([a-z"; //parentesi mancante
    final static String[] wordsNotPermittedList = {"testword" , "anothertest"};
    final static String[]  schemasNotPermittedValid = {"name"};
    final static String[]  schemasNotPermittedNotValid = {"age" , "city"};
    final static String[] prefixesList = {"testprefix"};
    final static String[] suffixesList = {"testsuffix"};
    final static String[] emptyList = {};

    //input parameters
    private int maxLength;
    private int minLength;
    private String pattern;
    private boolean uppercase;
    private boolean lowerCase;
    private List<String> wordsNotPermitted;
    private List<String> schemasNotPermitted;
    private List<String> prefixes;
    private List<String> suffixes;

    private String username;
    private Class<Exception> expectedException;
    private RuleConf confType;




   public AccountRuleTest(RuleConf confType, int minLength, int maxLength, String pattern, boolean uppercase, boolean lowercase, String[] wordsNotPermitted,
                          String[] schemasNotPermitted, String[] prefixes, String[] suffixes, String username,
                          Class<Exception> expectedException ) {
       this.confType = confType;
       this.minLength = minLength;
       this.maxLength = maxLength;
       this.pattern = pattern;
       this.uppercase = uppercase;
       this.lowerCase = lowercase;
       this.wordsNotPermitted = Arrays.asList(wordsNotPermitted);
       this.schemasNotPermitted = Arrays.asList(schemasNotPermitted);
       this.prefixes = Arrays.asList(prefixes);
       this.suffixes = Arrays.asList(suffixes);
       this.username = username;
       this.expectedException = expectedException;
   }

    @Parameterized.Parameters
    public static Collection<Object[]> getParameters() {
        return Arrays.asList(new Object[][]{
                // conf, minLength, maxLength, pattern, uppercase, lowercase, wordsNotPermitted, schemasNotPermitted, prefixes, suffixes, username, expectedException
                {RuleConf.CONF_VALID, 0, 0, null, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "UserNameTest0", null},
                {RuleConf.CONF_VALID, 0, -1, null, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "UserNameTest0", null},
                {RuleConf.CONF_VALID, 0, 1, null, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "A", null},
                {RuleConf.CONF_VALID, 0, 1, null, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "UserNameTest0", AccountPolicyException.class},
                {RuleConf.CONF_VALID, 1, 1, null, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "A", null},
                {RuleConf.CONF_VALID, 1, 1, null, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "UserNameTest0", AccountPolicyException.class},
                {RuleConf.CONF_VALID, 1, 0, null, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "A", null},
                {RuleConf.CONF_VALID, 1, 0, null, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "", AccountPolicyException.class},
                {RuleConf.CONF_VALID, 1, 2, null, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "Ab", null},
                {RuleConf.CONF_VALID, 1, 2, null, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "", AccountPolicyException.class},
                {RuleConf.CONF_VALID, -1, -1, null, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "UserNameTest0", null},
                {RuleConf.CONF_VALID, -1, -2, null, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "UserNameTest0", null},
                {RuleConf.CONF_VALID, -1, 0, null, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "UserNameTest0", null},

                {RuleConf.CONF_VALID, 0, 20, validRegex, true, true, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "Username", AccountPolicyException.class},
                {RuleConf.CONF_VALID, 0, 20, validRegex, false, true, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "username", null},
                {RuleConf.CONF_VALID, 0, 20, validRegex, false, true, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "Username", AccountPolicyException.class},
                {RuleConf.CONF_VALID, 0, 20, validRegex, true, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "USERNAME", null},
                {RuleConf.CONF_VALID, 0, 20, validRegex, true, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "Username", AccountPolicyException.class},
                {RuleConf.CONF_VALID, 0, 20, validRegex, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "Username.0", AccountPolicyException.class},
                {RuleConf.CONF_VALID, 0, 20, notValidRegex, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "Username", PatternSyntaxException.class},
                {RuleConf.CONF_VALID, 0, 20, null, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "Username", null},

                {RuleConf.CONF_VALID, 0, 20, validRegex, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "username", null},
                {RuleConf.CONF_VALID, 0, 20, validRegex, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "abtestwordab", AccountPolicyException.class},
                {RuleConf.CONF_VALID, 0, 20, validRegex, false, false, emptyList, schemasNotPermittedValid, prefixesList, suffixesList, "username", null},

                {RuleConf.CONF_VALID, 0, 20, validRegex, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "username", null},
                {RuleConf.CONF_VALID, 0, 20, validRegex, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "userMario", AccountPolicyException.class},
                {RuleConf.CONF_VALID, 0, 20, validRegex, false, false, wordsNotPermittedList, schemasNotPermittedNotValid, prefixesList, suffixesList, "user", null},
                {RuleConf.CONF_VALID, 0, 20, validRegex, false, false, wordsNotPermittedList, schemasNotPermittedNotValid, prefixesList, suffixesList, "userRoma", null},
                {RuleConf.CONF_VALID, 0, 20, validRegex, false, false, wordsNotPermittedList, emptyList, prefixesList, suffixesList, "user", null},

                {RuleConf.CONF_VALID, 0, 20, validRegex, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "username", null},
                {RuleConf.CONF_VALID, 0, 20, validRegex, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "testprefixUser", AccountPolicyException.class},
                {RuleConf.CONF_VALID, 0, 20, validRegex, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "usertestsuffix", AccountPolicyException.class},
                {RuleConf.CONF_VALID, 0, 20, validRegex, false, false, wordsNotPermittedList, schemasNotPermittedValid, emptyList, suffixesList, "username", null},
                {RuleConf.CONF_VALID, 0, 20, validRegex, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, emptyList, "username", null},

                {RuleConf.CONF_INVALID, 0, 0, null, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "UserNameTest0", IllegalArgumentException.class},

                {RuleConf.NULL, 0, 0, null, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "UserNameTest0", NullPointerException.class},
        });
    }

    enum RuleConf {
       CONF_VALID , CONF_INVALID , NULL
    }

    @Test
    public void enforceRulesTest() {
        DefaultAccountRule accountRule = new DefaultAccountRule();
        switch (this.confType) {
            case CONF_VALID :
            {
                //inizializzo le regole che l'account deve rispettare
                DefaultAccountRuleTestConf conf = new DefaultAccountRuleTestConf();
                conf.setMaxLength(this.maxLength);
                conf.setMinLength(this.minLength);
                conf.setPattern(this.pattern);
                conf.setAllUpperCase(this.uppercase);
                conf.setAllLowerCase(this.lowerCase);
                conf.setWordsNotPermitted(this.wordsNotPermitted);
                conf.setSchemasNotPermitted(this.schemasNotPermitted);
                conf.setPrefixes(this.prefixes);
                conf.setSuffixes(this.suffixes);
                accountRule.setConf(conf);
                break;
            }
            case CONF_INVALID: {
                TestAccountRuleConf conf = new TestAccountRuleConf();
                try {
                    accountRule.setConf(conf);
                } catch(Exception e) {
                    e.printStackTrace();
                    Assert.assertThat(e, CoreMatchers.instanceOf(expectedException));
                    return;
                }
                break;
            }
            case NULL: {
                try {
                    accountRule.setConf(null);
                } catch(Exception e) {
                    e.printStackTrace();
                    Assert.assertThat(e, CoreMatchers.instanceOf(expectedException));
                    return;
                }
            }
        }

        //creazione di uno user
        User user = new JPAUser();
        user.setUsername(this.username);

        //creo degli attributi/schemi da associare all'utente
        PlainAttrUniqueValue value = new JPAUPlainAttrUniqueValue();

        //setta il valore dell'attributo
        value.setStringValue("Mario");
        UPlainAttr attr = new JPAUPlainAttr();
        JPAPlainSchema schema = new JPAPlainSchema();

        //aggiunge il nome dello schema
        schema.setKey("name");
        attr.setSchema(schema);
        attr.setUniqueValue(value);

        //aggiunge l'attributo tra gli attributi associati all'utente
        user.add(attr);

        try {
            //verifico se le regole sono rispettate o meno
            accountRule.enforce(user);

        } catch(Exception e) {
            e.printStackTrace();
            Assert.assertThat(e, CoreMatchers.instanceOf(expectedException));
            return;
        }
        Assert.assertNull(expectedException);
    }

    //poichè non sono presenti i metodi setter di alcuni parametri, estendo la classe al fine di aggiungerli in quanto necessari per il testing
    class DefaultAccountRuleTestConf extends DefaultAccountRuleConf {

       private void setWordsNotPermitted(List<String> wordsNotPermitted) {
           this.getWordsNotPermitted().addAll(wordsNotPermitted);
       }

        private void setSchemasNotPermitted(List<String> schemasNotPermitted) {
            this.getSchemasNotPermitted().addAll(schemasNotPermitted);
        }

        private void setPrefixes(List<String> prefixes) {
            this.getPrefixesNotPermitted().addAll(prefixes);
        }

        private void setSuffixes(List<String> suffixes) {
            this.getSuffixesNotPermitted().addAll(suffixes);
        }
    }

    //classe utilizzata al fine di rappresentare una istanza non valida, ossia un'istanza di una classe che NON estende DefaultAccountRuleConf
    class TestAccountRuleConf extends AbstractAccountRuleConf {
        private static final long serialVersionUID = -1803957511928491978L;
    }
}
