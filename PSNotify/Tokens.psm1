#
# Tokens.psm1
#

function Merge-Tokens {
<#
.SYNOPSIS
Replaces tokens in a block of text with a specified value.
.DESCRIPTION
Replaces tokens in a block of text with a specified value.
.PARAMETER template
The block of text that contains text and tokens to be replaced.
.PARAMETER tokens
Token name/value hashtable.
.EXAMPLE
 $content = Get-Content .\template.txt | Merge-Tokens -tokens @{FirstName = 'foo'; LastName = 'bar'}
Pass template to function via pipeline.
.NOTES
  Original source: https://github.com/craibuc/PsTokens/blob/master/Merge-Tokens.ps1
#>

    [CmdletBinding()] 
    
    param (
        [Parameter(Mandatory=$True, ValueFromPipeline=$true)]
        [AllowEmptyString()]
        [String] $Template,

        [Parameter(Mandatory=$true)]
        [HashTable] $Tokens
    ) 

    begin {
      Write-Verbose "$($MyInvocation.MyCommand.Name)::Begin"

      function Script:is_iterable_token($token) {
        #if ($match.Value -match "^\s*{{\s*@?") {
        if ($token -match "^[{]{2}") {
          $count = 2 # The input token is wrapped: {{token_name remainder {{inside stuff}}}}
        } else {
          $count = 1 # The input token had been unwrapped: remainder {{inside stuff}}
        }

        if ([RegEx]::Matches($token, "[{]{2}").Count -ge $count) {
          return $true
        }
        return $false
      }

      function Script:unwrap_token($token) {
        $token_name = Script:get_token_name $token
        $regex_string = "^\s*{{\s*@?$token_name(?<remainder>.*)}}$"
        return [RegEx]::Match($token, $regex_string, "Singleline").Groups['remainder'].Value
      }

      function Script:get_token_name($token) {
        return [RegEx]::Match($token, "^\s*{{\s*@?(?<token_name>([^\s}{]|(?<d>[}{])(?!\k<d>))+)").Groups['token_name'].Value
      }
    }

    process {
      Write-Verbose "$($MyInvocation.MyCommand.Name)::Process" 

      # adapted based on this Stackoverflow answer: http://stackoverflow.com/a/29041580/134367
      <#
      [regex]::Replace( $template, '{{(?<tokenName>[\w\.]+)}}', {
        # {{TOKEN}}
        param($match)

        $tokenName = $match.Groups['tokenName'].Value
        Write-Debug $tokenName
              
        $tokenValue = Invoke-Expression "`$tokens.$tokenName"
        Write-Debug $tokenValue

        if ($tokenValue) {
          # there was a value; return it
          return $tokenValue
        } 
        else {
          # non-matching token; return token
          return $match
        }
      })
      #>

      # 2do: this breaks if tokens aren't seperated by white space (e.g. {{test}}{{test2}} doesn't work)
      # Working-ish: "(((?<Open>\{{2})([^}{]|(?<![}{])[}{](?![}{]))*)+((?<Close-Open>\}{2})(?(Open)([^}{]|(?<![}{])[}{](?![}{])))*)+)+(?(Open)(?!))"
      [regex]::Replace( $template, "(((?(Close)(?(Open)|(?>![}]{2})))(?<Open>\{{2})([^}{]|(?<![}{])[}{](?![}{]))*)+((?<Close-Open>\}{2})(?(Open)([^}{]|(?<![}{])[}{](?![}{])))*)+)+(?(Open)(?!))", {
        Param($match)

        $token_name = Script:get_token_name $match.Value

        if (-not $Tokens.ContainsKey($token_name)) {
          # Token doesn't exist in the provided hashtable of tokens. Return an empty string
          #return $match.Value
          return ""
        }

        $replacement_string = ""
        $token_remainder = Script:unwrap_token $match.Value

        $Tokens[$token_name] | % {
          $token_value = $_
                
          # If we're looking at a recurring pattern, recurse
          if (Script:is_iterable_token $match.Value) {
            $token_value | % {
              # Validate the input type - the only valid input is a hashtable
              if (-not ($_.GetType() -eq [hashtable])) {
                # It might be more useful to receive a message with unmatched tokens, instead of no message at all
                #throw [System.ArgumentException] "The provided input for $token_name should be a hashtable, but is of type $($_.GetType().Name)"
                # 2do: log
                return $match.Value
              }

              # Recurse by calling self
              Merge-Tokens -tokens $_ -template $token_remainder 
            } | % { $replacement_string += $_ }
                
          # If the pattern we're looking is not recurring...
          } else {
            $token_value | % { 
              # Should be a single-valued object (not an array or a collection)
              if ($_.GetType().FullName -Match "collection|array|\[\]") {
                # Here again, it might be more useful to receive a message with unmatched tokens, instead of no message at all
                # 2do: log
                return $match.Value
              }

              $replacement_string += ($_ + $token_remainder) 
            }
          }
        }

        return $replacement_string
      })
    }

    end { Write-Verbose "$($MyInvocation.MyCommand.Name)::End" }

}

Export-ModuleMember -Function @(
  "Merge-Tokens"
)