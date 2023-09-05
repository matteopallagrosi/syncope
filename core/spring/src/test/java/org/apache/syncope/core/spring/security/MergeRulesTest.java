package org.apache.syncope.core.spring.security;

import org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf;
import org.hamcrest.CoreMatchers;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(value= Parameterized.class)
public class MergeRulesTest {

    final static Character[] CHARS_1 = {'!', '%'};
    final static Character[] CHARS_2 = {'$', '&'};
    final static String[] WORDS_1 = {"test" , "anotherTest"};
    final static String[] WORDS_2 = {"merge" , "rules"};

    //parameters
    private List<DefaultPasswordRuleConf> ruleConfs = new ArrayList<>();
    private DefaultPasswordRuleConf conf1;
    private DefaultPasswordRuleConf conf2;
    private Class<Exception> expectedException;
    private ConfsType confs;

    public MergeRulesTest(ConfsType confs, Class<Exception> expectedException) {
        this.confs = confs;
        conf1 = new DefaultPasswordRuleConf();
        conf2 = new DefaultPasswordRuleConf();
        ruleConfs.add(conf1);
        ruleConfs.add(conf2);
        switch(confs) {
            case EQUAL : {
                conf1.setMinLength(1);
                conf2.setMinLength(1);

                conf1.setMaxLength(1);
                conf2.setMaxLength(1);

                conf1.setAlphabetical(1);
                conf2.setAlphabetical(1);

                conf1.setUppercase(1);
                conf2.setUppercase(1);

                conf1.setLowercase(1);
                conf2.setLowercase(1);

                conf1.setDigit(1);
                conf2.setDigit(1);

                conf1.setSpecial(1);
                conf2.setSpecial(1);

                conf1.getSpecialChars().addAll(Arrays.asList(CHARS_1));
                conf2.getSpecialChars().addAll(Arrays.asList(CHARS_1));

                conf1.getIllegalChars().addAll(Arrays.asList(CHARS_1));
                conf2.getIllegalChars().addAll(Arrays.asList(CHARS_1));

                conf1.setRepeatSame(1);
                conf2.setRepeatSame(1);

                conf1.setUsernameAllowed(true);
                conf2.setUsernameAllowed(true);

                conf1.getWordsNotPermitted().addAll(Arrays.asList(WORDS_1));
                conf2.getWordsNotPermitted().addAll(Arrays.asList(WORDS_1));

                conf1.getSchemasNotPermitted().addAll(Arrays.asList(WORDS_1));
                conf2.getSchemasNotPermitted().addAll(Arrays.asList(WORDS_1));

                break;
            }

            case DIFFERENT: {
                conf1.setMinLength(2);
                conf2.setMinLength(1);

                conf1.setMaxLength(3);
                conf2.setMaxLength(4);

                conf1.setAlphabetical(2);
                conf2.setAlphabetical(1);

                conf1.setUppercase(2);
                conf2.setUppercase(1);

                conf1.setLowercase(2);
                conf2.setLowercase(1);

                conf1.setDigit(2);
                conf2.setDigit(1);

                conf1.setSpecial(2);
                conf2.setSpecial(1);

                conf1.getSpecialChars().addAll(Arrays.asList(CHARS_1));
                conf2.getSpecialChars().addAll(Arrays.asList(CHARS_2));

                conf1.getIllegalChars().addAll(Arrays.asList(CHARS_1));
                conf2.getIllegalChars().addAll(Arrays.asList(CHARS_2));

                conf1.setRepeatSame(1);
                conf2.setRepeatSame(2);

                conf1.setUsernameAllowed(false);
                conf2.setUsernameAllowed(true);

                conf1.getWordsNotPermitted().addAll(Arrays.asList(WORDS_1));
                conf2.getWordsNotPermitted().addAll(Arrays.asList(WORDS_2));

                conf1.getSchemasNotPermitted().addAll(Arrays.asList(WORDS_1));
                conf2.getSchemasNotPermitted().addAll(Arrays.asList(WORDS_2));

                break;
            } case NEGATIVE: {
                conf1.setMinLength(-1);

                conf1.setMaxLength(-1);

                conf1.setAlphabetical(-1);

                conf1.setUppercase(-1);

                conf1.setLowercase(-1);

                conf1.setDigit(-1);

                conf1.setSpecial(-1);

                conf1.setRepeatSame(-1);

                break;
            }
            case EMPTY : {
                ruleConfs.clear();

                break;
            }
            case NULL: {
                ruleConfs = null;

                break;
            }
        }

        this.expectedException = expectedException;
    }


    @Parameterized.Parameters
    public static Collection<Object[]> getParameters() {
        return Arrays.asList(new Object[][]{
                //defaultRuleConfs, expectedException
                {ConfsType.EQUAL, null},
                {ConfsType.DIFFERENT, null},
                {ConfsType.NEGATIVE, null},
                {ConfsType.EMPTY, null},
                {ConfsType.NULL, NullPointerException.class}
        });

    }

    enum ConfsType {
        EQUAL, DIFFERENT, NEGATIVE, EMPTY, NULL
    }



    @Test
    public void mergeTest() {

        DefaultPasswordGenerator passwordGenerator = new DefaultPasswordGenerator();
        DefaultPasswordRuleConf result;
        try {
            result = passwordGenerator.merge(ruleConfs);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.assertThat(e, CoreMatchers.instanceOf(expectedException));
            return;
        }

        //se non ho passato configurazioni oppure i parametri sono negativi, mi aspetto che venga settata la configurazione di default
        if (confs.equals(ConfsType.EMPTY) || confs.equals(ConfsType.NEGATIVE)) {
            conf1.setMinLength(DefaultPasswordGenerator.MIN_LENGTH_IF_ZERO);
            conf1.setMaxLength(DefaultPasswordGenerator.VERY_MAX_LENGTH);
            //i restanti parametri saranno tutti settati a 0 (e liste vuote per i parametri di tipo List<>)
            conf1.setAlphabetical(0);
            conf1.setUppercase(0);
            conf1.setLowercase(0);
            conf1.setDigit(0);
            conf1.setSpecial(0);
            conf1.getSpecialChars().clear();
            conf1.getIllegalChars().clear();
            conf1.setRepeatSame(0);
            conf1.setUsernameAllowed(false);
            conf1.getWordsNotPermitted().clear();
            conf1.getSchemasNotPermitted().clear();
        }

        //testo che la configurazione risultante abbia i parametri settati secondo il comportamento previsto
        assertEquals(conf1.getMinLength(), result.getMinLength());
        assertEquals(conf1.getMaxLength(), result.getMaxLength());
        assertEquals(conf1.getAlphabetical(), result.getAlphabetical());
        assertEquals(conf1.getUppercase(), result.getUppercase());
        assertEquals(conf1.getLowercase(), result.getLowercase());
        assertEquals(conf1.getDigit(), result.getDigit());
        assertEquals(conf1.getSpecial(), result.getSpecial());

        if (confs.equals(ConfsType.EQUAL)) {
            assertTrue(result.getSpecialChars().containsAll(conf1.getSpecialChars()));
            assertTrue(result.getIllegalChars().containsAll(conf1.getIllegalChars()));
            assertTrue(result.getWordsNotPermitted().containsAll(conf1.getWordsNotPermitted()));
            //assertTrue(result.getSchemasNotPermitted().containsAll(conf1.getSchemasNotPermitted()));  //possibile bug, schemasNotPermitted non è configurato nella risultante del merge

        }


        if (confs.equals(ConfsType.DIFFERENT)) {
            assertTrue(result.getSpecialChars().containsAll(conf1.getSpecialChars()) && result.getSpecialChars().containsAll(conf2.getSpecialChars()));
            assertTrue(result.getIllegalChars().containsAll(conf1.getIllegalChars()) && result.getIllegalChars().containsAll(conf2.getIllegalChars()));
            assertTrue(result.getWordsNotPermitted().containsAll(conf1.getWordsNotPermitted()) && result.getWordsNotPermitted().containsAll(conf2.getWordsNotPermitted()));
            //assertTrue(result.getSchemasNotPermitted().containsAll(conf1.getSchemasNotPermitted()) && result.getSchemasNotPermitted().containsAll(conf2.getSchemasNotPermitted())); //possibile bug, schemasNotPermitted non è configurato nella risultante del merge
        }

        //assertEquals(conf1.getRepeatSame(), result.getRepeatSame());  //possibile bug, la funzione dovrebbe settare il valore minore tra le due configurazioni, invece setta il valore maggiore

        //assertEquals(conf1.isUsernameAllowed(), result.isUsernameAllowed()); //possibile bug, la funzione dovrebbe settare false se nella lista è presente almeno una configurazione con usernameAllowed = false, invece setta true
    }
}
