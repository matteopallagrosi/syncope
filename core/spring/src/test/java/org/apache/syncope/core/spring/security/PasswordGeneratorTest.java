package org.apache.syncope.core.spring.security;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf;
import org.apache.syncope.common.lib.policy.PasswordRuleConf;
import org.apache.syncope.common.lib.types.ImplementationEngine;
import org.apache.syncope.common.lib.types.PolicyType;
import org.apache.syncope.core.persistence.api.entity.Implementation;
import org.apache.syncope.core.persistence.api.entity.policy.PasswordPolicy;
import org.apache.syncope.core.provisioning.api.rules.PasswordRule;
import org.apache.syncope.core.provisioning.api.serialization.POJOHelper;
import org.apache.syncope.core.spring.implementation.ImplementationManager;
import org.apache.syncope.core.spring.policy.DefaultPasswordRule;
import org.hamcrest.CoreMatchers;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.MockedStatic;

import java.nio.BufferOverflowException;
import java.util.*;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(value= Parameterized.class)
public class PasswordGeneratorTest {
    final static Character[] emptyList = {};
    final static int NOT_INITIALIZED = Integer.MIN_VALUE;  //valore fittizio necessario ad identificare i casi in cui non inizializziamo minLength o maxLength
    final static Character[] specialChars = {'.' , '_'};
    final static Character[] commonChars = {'a' , 'B'};

    //parameters
    private DefaultPasswordRuleConf conf;
    private Class<Exception> expectedException;
    private List<PasswordPolicy> policies = new ArrayList<PasswordPolicy>();
    private boolean noPolicies = false;

    public PasswordGeneratorTest(PoliciesType policy, int minLength, int maxLength, int alphabetical, int uppercase, int lowercase, int digit, int special, Character[] specialChars, Class<Exception> expectedException) {
        switch(policy) {
            case VALID: {
                DefaultPasswordRuleConf passwordRuleConf = new DefaultPasswordRuleConf();
                if (minLength != NOT_INITIALIZED) {
                    passwordRuleConf.setMinLength(minLength);
                }
                if (maxLength != NOT_INITIALIZED) {
                    passwordRuleConf.setMaxLength(maxLength);
                }
                passwordRuleConf.setAlphabetical(alphabetical);
                passwordRuleConf.setUppercase(uppercase);
                passwordRuleConf.setLowercase(lowercase);
                passwordRuleConf.setDigit(digit);
                passwordRuleConf.setSpecial(special);
                passwordRuleConf.getSpecialChars().addAll(Arrays.asList(specialChars));
                this.conf = passwordRuleConf;

                break;
            }
            case INVALID: {
                DefaultPasswordRuleConf passwordRuleConf = new DefaultPasswordRuleConf();
                //il numero di caratteri da inserire eccede la lunghezza scelta (per questo la policy è non valida)
                passwordRuleConf.setMinLength(10);
                passwordRuleConf.setAlphabetical(3);
                passwordRuleConf.setUppercase(3);
                passwordRuleConf.setLowercase(3);
                passwordRuleConf.setDigit(3);
                this.conf = passwordRuleConf;

                break;
            }
            case EMPTY: {
                noPolicies = true;

                break;
            }
            case NULL: {
                policies = null;

                break;
            }
        }

        this.expectedException = expectedException;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> getParameters() {
        return Arrays.asList(new Object[][]{
                // policies, minLength, maxLength, alphabetical, uppercase, lowercase, digit, special, specialChars, expectedException

                //minLength e maxLength approccio multidimensionale (escludendo combinazioni non possibili)
                {PoliciesType.VALID, NOT_INITIALIZED, NOT_INITIALIZED, 2, 2, 2, 2, 0, emptyList, null},
                {PoliciesType.VALID, -1, -2, 2, 2, 2, 2, 0, emptyList, null},
                {PoliciesType.VALID, -1, -1, 2, 2, 2, 2, 0, emptyList, null},
                {PoliciesType.VALID, -1, 0, 2, 2, 2, 2, 0, emptyList, null},
                {PoliciesType.VALID, -1, NOT_INITIALIZED, 2, 2, 2, 2, 0, emptyList, null},
                {PoliciesType.VALID, 0, -1, 2, 2, 2, 2, 0, emptyList, null},
                {PoliciesType.VALID, 0, 0, 2, 2, 2, 2, 0, emptyList, null},
                {PoliciesType.VALID, 0, 1, 1, 0, 0, 0, 0, emptyList, null},  //se la lunghezza minima è 0, viene settato al valore di default, se però questo è superiore alla lunghezza massima, minLength = maxLength
                {PoliciesType.VALID, 0, NOT_INITIALIZED, 2, 2, 2, 2, 0, emptyList, null},
                {PoliciesType.VALID, 1, 0, 1, 0, 0, 0, 0, emptyList, null},
                {PoliciesType.VALID, 1, 1, 1, 0, 0, 0, 0, emptyList, null},
                {PoliciesType.VALID, 1, 2, 1, 0, 0, 0, 0, emptyList, null},
                {PoliciesType.VALID, 1, NOT_INITIALIZED, 1, 0, 0, 0, 0, emptyList, null},
                {PoliciesType.VALID, 2, 1, 2, 0, 0, 0, 0, emptyList, null},
                {PoliciesType.VALID, 2, 0, 2, 0, 0, 0, 0, emptyList, null},
                {PoliciesType.VALID, 2, 3, 2, 0, 0, 0, 0, emptyList, null},
                {PoliciesType.VALID, 2, NOT_INITIALIZED, 2, 0, 0, 0, 0, emptyList, null},

                //approccio unidimensionale per il parametro alphabetical
                {PoliciesType.VALID, 0, 0, 0, 2, 2, 2, 2, specialChars, null},
                {PoliciesType.VALID, 0, 0, -1, 2, 2, 2, 2, specialChars, null},
                {PoliciesType.VALID, 1, 0, 1, 0, 0, 0, 0, emptyList, null},
                {PoliciesType.VALID, 2, 0, 2, 0, 0, 0, 0, emptyList, null},

                //approccio unidimensionale per il parametro uppercase
                {PoliciesType.VALID, 0, 0, 2, 0, 2, 2, 2, specialChars, null},
                {PoliciesType.VALID, 0, 0, 2, -1, 2, 2, 2, specialChars, null},
                {PoliciesType.VALID, 1, 0, 0, 1, 0, 0, 0, emptyList, null},
                {PoliciesType.VALID, 2, 0, 0, 2, 0, 0, 0, emptyList, null},

                //approccio unidimensionale per il parametro lowercase
                {PoliciesType.VALID, 0, 0, 2, 2, 0, 2, 2, specialChars, null},
                {PoliciesType.VALID, 0, 0, 2, 2, -1, 2, 2, specialChars, null},
                {PoliciesType.VALID, 1, 0, 0, 0, 1, 0, 0, emptyList, null},
                {PoliciesType.VALID, 2, 0, 0, 0, 2, 0, 0, emptyList, null},

                //approccio unidimensionale per il parametro digit
                {PoliciesType.VALID, 0, 0, 2, 2, 2, 0, 2, specialChars, null},
                {PoliciesType.VALID, 0, 0, 2, 2, 2, -1, 2, specialChars, null},
                {PoliciesType.VALID, 1, 0, 0, 0, 0, 1, 0, emptyList, null},
                {PoliciesType.VALID, 2, 0, 0, 0, 0, 2, 0, emptyList, null},

                //approccio multidimensionale per i parametri special e specialChars correllati tra loro (numero pari a 'special' di caratteri speciali devono essere estratti dalla lista 'specialChars')
                {PoliciesType.VALID, 0, 0, 2, 2, 2, 2, 0, emptyList, null},
                {PoliciesType.VALID, 0, 0, 2, 2, 2, 2, 0, specialChars, null},
                {PoliciesType.VALID, 0, 0, 2, 2, 2, 2, 0, commonChars, null},
                {PoliciesType.VALID, 0, 0, 2, 2, 2, 2, -1, emptyList, null},
                {PoliciesType.VALID, 0, 0, 2, 2, 2, 2, -1, specialChars, null},
                {PoliciesType.VALID, 0, 0, 2, 2, 2, 2, -1, commonChars, null},
                {PoliciesType.VALID, 0, 0, 2, 2, 2, 1, 1, emptyList, IllegalArgumentException.class}, //deve prelevare dei caratteri speciali, ma nessun carattere gli è stato fornito
                {PoliciesType.VALID, 0, 0, 2, 2, 2, 1, 1, specialChars, null},
                {PoliciesType.VALID, 0, 0, 2, 2, 2, 1, 1, commonChars, null},
                {PoliciesType.VALID, 0, 0, 2, 2, 2, 0, 2, emptyList, IllegalArgumentException.class}, //deve prelevare dei caratteri speciali, ma nessun carattere gli è stato fornito
                {PoliciesType.VALID, 0, 0, 2, 2, 2, 0, 2, specialChars, null},
                {PoliciesType.VALID, 0, 0, 2, 2, 2, 0, 2, commonChars, null},

                //mi aspetto un eccezione BufferOverFlowException perchè ho richiesto di inserire più caratteri della lunghezza richiesta per la password
                {PoliciesType.INVALID, 0, 0, 0, 0, 0, 0, 0, null, BufferOverflowException.class}, //quando la policy è non valida, la configurazione è definita direttamente nel costruttore

                {PoliciesType.EMPTY, 0, 0, 0, 0, 0, 0, 0, null, null},

                {PoliciesType.NULL, 0, 0, 0, 0, 0, 0, 0, null, NullPointerException.class} //quando la policy è nulla, i restanti parametri sono ignorati


        });
    }

    enum PoliciesType {
        VALID, INVALID, EMPTY, NULL
    }

    @Test
    public void generatePasswordTest() {

        String serialized = POJOHelper.serialize(this.conf, new TypeReference<DefaultPasswordRuleConf>(){});

        //passwordRuleConf = POJOHelper.deserialize(serialized, DefaultPasswordRuleConf.class);

        //System.out.println(passwordRuleConf.getMinLength());

        Implementation mockedRule = mock(Implementation.class);

        //la regola è implementata in un oggetto serializzato, a questo livello di astrazione non ci interessa quale classe implementa l'interfaccia Rule, qualunque essa sia
        //ci aspettiamo che ritorni la "rule" serializzata come stringa
        when(mockedRule.getBody()).thenReturn(serialized);
        when(mockedRule.getEngine()).thenReturn(ImplementationEngine.JAVA);
        PasswordPolicy policy = new TestPolicy();
        policy.add(mockedRule);

        if (policies != null && !noPolicies) {
            policies.add(policy);
        }

        //Mocko la classe ImplementationManager su cui la costruzione delle regole si appoggia (per il test di unità suppongo che ImplementationManager funzioni come mi aspetto)
        try (MockedStatic mocked = mockStatic(ImplementationManager.class)) {
            mocked.when(()->ImplementationManager.buildPasswordRule(any(), any(), any())).thenAnswer(input -> {
                PasswordRuleConf conf = POJOHelper.deserialize(mockedRule.getBody(), PasswordRuleConf.class);
                PasswordRule rule = new DefaultPasswordRule();
                rule.setConf(conf);
                return Optional.of(rule);
            });

            DefaultPasswordGenerator passwordGenerator = new DefaultPasswordGenerator();
            String generatedPassword;
            try {
                generatedPassword = passwordGenerator.generate(policies);
            } catch (Exception e) {
                e.printStackTrace();
                Assert.assertThat(e, CoreMatchers.instanceOf(expectedException));
                return;
            }

            //verifico che la password generata rispetti i vincoli imposti
            System.out.println("La password generata è:" + generatedPassword);
            if (!noPolicies) {
                if (conf.getAlphabetical() < 0) {
                    conf.setAlphabetical(0);
                }
                if (conf.getUppercase() < 0) {
                    conf.setUppercase(0);
                }
                if (conf.getLowercase() < 0) {
                    conf.setLowercase(0);
                }
                if (conf.getDigit() < 0) {
                    conf.setDigit(0);
                }
                if (conf.getSpecial() < 0) {
                    conf.setSpecial(0);
                }
                assertTrue(countAlphabetCharacters(generatedPassword) >= conf.getAlphabetical());
                assertEquals(conf.getDigit(), countDigits(generatedPassword));
                assertTrue(countUppercaseCharacters(generatedPassword) >= conf.getUppercase());
                assertTrue(countLowercaseCharacters(generatedPassword) >= conf.getLowercase());
                assertTrue(countLowercaseCharacters(generatedPassword) >= conf.getLowercase());
                if (conf.getSpecialChars().containsAll(Arrays.asList(commonChars))) {
                    assertTrue(countSpecialCharacters(generatedPassword, conf.getSpecialChars()) >= conf.getSpecial());
                } else {
                    assertEquals(conf.getSpecial(), countSpecialCharacters(generatedPassword, conf.getSpecialChars()));
                }
            }
            //altrimenti dovrebbe essere stata usata la policy di default
            else {
                assertEquals(DefaultPasswordGenerator.MIN_LENGTH_IF_ZERO/2, countAlphabetCharacters(generatedPassword));
                assertEquals(DefaultPasswordGenerator.MIN_LENGTH_IF_ZERO/2, countDigits(generatedPassword));
            }
        }
    }

    public static int countAlphabetCharacters(String str) {
        int count = 0;
        for (int i = 0; i < str.length(); i++) {
            char c = str.charAt(i);
            if (Character.isLetter(c)) { // Check if the character is a letter (alphabetical character)
                count++;
            }
        }
        return count;
    }

    public static int countDigits(String str) {
        int count = 0;
        for (int i = 0; i < str.length(); i++) {
            char c = str.charAt(i);
            if (Character.isDigit(c)) { // Check if the character is a digit
                count++;
            }
        }
        return count;
    }

    public static int countUppercaseCharacters(String str) {
        int count = 0;
        for (int i = 0; i < str.length(); i++) {
            char c = str.charAt(i);
            if (Character.isUpperCase(c)) { // Check if the character is uppercase
                count++;
            }
        }
        return count;
    }

    public static int countLowercaseCharacters(String str) {
        int count = 0;
        for (int i = 0; i < str.length(); i++) {
            char c = str.charAt(i);
            if (Character.isLowerCase(c)) { // Check if the character is uppercase
                count++;
            }
        }
        return count;
    }

    public static int countSpecialCharacters(String str, List<Character> charList) {
        int count = 0;

        for (int i = 0; i < str.length(); i++) {
            char c = str.charAt(i);
            if (charList.contains(c)) { // Check if the character is in the list
                count++;
            }
        }

        return count;
    }



    class TestPolicy implements PasswordPolicy {

        private List<Implementation> rules = new ArrayList<>();

        @Override
        public String getKey() {
            return null;
        }

        @Override
        public boolean isAllowNullPassword() {
            return false;
        }

        @Override
        public void setAllowNullPassword(boolean allowNullPassword) {

        }

        @Override
        public int getHistoryLength() {
            return 0;
        }

        @Override
        public void setHistoryLength(int historyLength) {

        }

        @Override
        public boolean add(Implementation rule) {
            return rules.contains(rule) || rules.add(rule);
        }

        @Override
        public List<? extends Implementation> getRules() {
            return rules;
        }

        @Override
        public String getName() {
            return null;
        }

        @Override
        public void setName(String name) {

        }
    }



}
