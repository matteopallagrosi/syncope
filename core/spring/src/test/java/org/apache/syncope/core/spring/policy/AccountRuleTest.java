package org.apache.syncope.core.spring.policy;

import org.apache.syncope.common.lib.policy.DefaultAccountRuleConf;
import org.apache.syncope.common.lib.to.UserTO;
import org.apache.syncope.core.persistence.api.entity.PlainAttr;
import org.apache.syncope.core.persistence.api.entity.PlainAttrUniqueValue;
import org.apache.syncope.core.persistence.api.entity.PlainAttrValue;
import org.apache.syncope.core.persistence.api.entity.PlainSchema;
import org.apache.syncope.core.persistence.api.entity.user.UPlainAttr;
import org.apache.syncope.core.persistence.api.entity.user.User;
import org.apache.syncope.core.persistence.jpa.entity.JPAPlainSchema;
import org.apache.syncope.core.persistence.jpa.entity.anyobject.JPAAPlainAttr;
import org.apache.syncope.core.persistence.jpa.entity.anyobject.JPAAPlainAttrValue;
import org.apache.syncope.core.persistence.jpa.entity.user.JPAUPlainAttr;
import org.apache.syncope.core.persistence.jpa.entity.user.JPAUPlainAttrUniqueValue;
import org.apache.syncope.core.persistence.jpa.entity.user.JPAUser;
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




   public AccountRuleTest(int minLength, int maxLength, String pattern, boolean uppercase, boolean lowercase, String[] wordsNotPermitted,
                          String[] schemasNotPermitted, String[] prefixes, String[] suffixes, String username,
                          Class<Exception> expectedException ) {
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
                // minLength, maxLength, pattern, uppercase, lowercase, wordsNotPermitted, schemasNotPermitted, prefixes, suffixes, username, expectedException
                {0, 0, null, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "UserNameTest0", null},
                {0, -1, null, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "UserNameTest0", null},
                {0, 1, null, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "A", null},
                {0, 1, null, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "UserNameTest0", AccountPolicyException.class},
                {1, 1, null, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "A", null},
                {1, 1, null, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "UserNameTest0", AccountPolicyException.class},
                {1, 0, null, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "A", null},
                {1, 0, null, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "", AccountPolicyException.class},
                {1, 2, null, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "Ab", null},
                {1, 2, null, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "", AccountPolicyException.class},
                {-1, -1, null, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "UserNameTest0", null},
                {-1, -2, null, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "UserNameTest0", null},
                {-1, 0, null, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "UserNameTest0", null},

                {0, 20, validRegex, true, true, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "Username", AccountPolicyException.class},
                {0, 20, validRegex, false, true, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "username", null},
                {0, 20, validRegex, false, true, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "Username", AccountPolicyException.class},
                {0, 20, validRegex, true, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "USERNAME", null},
                {0, 20, validRegex, true, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "Username", AccountPolicyException.class},
                {0, 20, notValidRegex, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "Username", PatternSyntaxException.class},
                {0, 20, null, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "Username", null},

                {0, 20, validRegex, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "username", null},
                {0, 20, validRegex, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "abtestwordab", AccountPolicyException.class},
                {0, 20, validRegex, false, false, emptyList, schemasNotPermittedValid, prefixesList, suffixesList, "username", null},

                {0, 20, validRegex, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "username", null},
                {0, 20, validRegex, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "userMario", AccountPolicyException.class},
                {0, 20, validRegex, false, false, wordsNotPermittedList, schemasNotPermittedNotValid, prefixesList, suffixesList, "user", null},
                {0, 20, validRegex, false, false, wordsNotPermittedList, schemasNotPermittedNotValid, prefixesList, suffixesList, "userRoma", null},
                {0, 20, validRegex, false, false, wordsNotPermittedList, emptyList, prefixesList, suffixesList, "user", null},

                {0, 20, validRegex, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "username", null},
                {0, 20, validRegex, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "testprefixUser", AccountPolicyException.class},
                {0, 20, validRegex, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, suffixesList, "usertestsuffix", AccountPolicyException.class},
                {0, 20, validRegex, false, false, wordsNotPermittedList, schemasNotPermittedValid, emptyList, suffixesList, "username", null},
                {0, 20, validRegex, false, false, wordsNotPermittedList, schemasNotPermittedValid, prefixesList, emptyList, "username", null},
        });
    }

    @Test
    public void enforceRulesTest() {
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


        DefaultAccountRule accountRule = new DefaultAccountRule();
        accountRule.setConf(conf);

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
            assertThat(e, instanceOf(expectedException));
            return;
        }
        assertNull(expectedException);
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

}
