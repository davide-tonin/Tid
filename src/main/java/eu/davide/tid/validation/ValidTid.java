package eu.davide.tid.validation;


import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;


@Documented
@Constraint(validatedBy = TidValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidTid
{

    String message() default "Tid verification failed";

    String type();

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

}