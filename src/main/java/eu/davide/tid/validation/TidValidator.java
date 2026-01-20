package eu.davide.tid.validation;


import eu.davide.tid.Tid;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.nio.charset.StandardCharsets;
import java.util.UUID;


public class TidValidator implements ConstraintValidator<ValidTid, UUID>
{

    public static Tid tidInstance;
    private byte[] typeBytes;

    @Override
    public void initialize(ValidTid constraint)
    {
        this.typeBytes = constraint.type().getBytes(StandardCharsets.UTF_8);
    }


    @Override
    public boolean isValid(UUID value, ConstraintValidatorContext context)
    {
        if (value == null) return true;

        if (tidInstance == null)
        {
            throw new IllegalStateException("TidValidator.tidInstance not set!");
        }

        return tidInstance.decode(value, typeBytes).isValid();
    }

}