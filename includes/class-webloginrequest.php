<?php

namespace DIT;

/**
 * Web Login Request class for steganography-based login
 * Based on developer instructions for new login logic
 */
class WebLoginRequest
{
    /**
     * @var int Login type (role_id: 1=User, 2=Customer, 3=Administrator)
     */
    public $LoginType;

    /**
     * @var string Plain text password
     */
    public $Password;

    /**
     * @var string User email
     */
    public $Email;

    /**
     * Constructor
     * 
     * @param string $email User email
     * @param string $password Plain text password
     * @param int $loginType Login type (role_id)
     */
    public function __construct($email, $password, $loginType)
    {
        $this->Email = $email;
        $this->Password = $password;
        $this->LoginType = (int)$loginType;
    }

    /**
     * Convert to array for JSON serialization
     * 
     * @return array
     */
    public function toArray()
    {
        return [
            'LoginType' => $this->LoginType,
            'Password' => $this->Password,
            'Email' => $this->Email
        ];
    }

    /**
     * Serialize to JSON string
     * 
     * @return string|false JSON string or false on failure
     */
    public function toJson()
    {
        return json_encode($this->toArray());
    }

    /**
     * Validate request data
     * 
     * @return bool
     */
    public function isValid()
    {
        return !empty($this->Email) &&
            !empty($this->Password) &&
            is_numeric($this->LoginType) &&
            $this->LoginType > 0;
    }
}
