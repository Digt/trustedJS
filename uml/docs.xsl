<?xml version="1.0" encoding="UTF-8"?>

<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

  <xsl:template match="package|modelStoreModel">
    <html>
      <head>
        <title>Обозреватель</title>
        <style>
          *{
          font-family: Century Gothic;
          }
          body{
          min-width:960px;
          }
          .content{
          padding:0px 40px;
          }
          .method{
          background: url('Images/ImageSprite.png') no-repeat scroll -1631px -3px;
          width: 16px;
          height: 11px;
          overflow: hidden;
          }
          .property{
          background: url('Images/ImageSprite.png') no-repeat scroll -1700px -3px;
          width: 16px;
          height: 16px;
          overflow: hidden;
          }
          .class{
          background: url('Images/ImageSprite.png') no-repeat scroll -1406px -3px;
          width: 18px;
          height: 16px;
          overflow: hidden;
          }
          .enum{
          background: url('Images/ImageSprite.png') no-repeat scroll -1453px -3px;
          width: 18px;
          height: 16px;
          overflow: hidden;
          }
          .param{
          background: url('Images/ImageSprite.png') no-repeat scroll -1516px -3px;
          width: 18px;
          height: 16px;
          overflow: hidden;
          }
          table{
          border-collapse: collapse;
          font-size: 15px;
          }
          th{
          color: white;
          background-color: #555555;
          padding: 10px 0px;
          }
          td{
          border: 1px solid #d4d4d4;
          padding:10px;
          }
          .method_params img{
          margin-right: 5px;
          }
          .method_params .name{
          font-style: italic;
          }
          .code{
          background:#EEEEEE;
          border: solid 1px #CCCCCC;
          padding:15px;
          font: normal 18px Courier New;
          }
          .code *{
          font: normal 18px Courier New;
          }
        </style>
      </head>
      <body>
        <h2>
          Элементы пакета :: <xsl:value-of select="@name"/>
        </h2>
        <div class="content">
          <xsl:apply-templates select="packagedElements" mode="class"/>
          <xsl:apply-templates select="packagedElements" mode="enumeration"/>
          <!-- Детализация классов -->
          <xsl:for-each select="packagedElements//class">
            <xsl:apply-templates select="."/>
          </xsl:for-each>
          <!-- Перечислений -->
          <xsl:for-each select="packagedElements//enumeration">
            <xsl:apply-templates select="."/>
          </xsl:for-each>
        </div>
      </body>
    </html>
  </xsl:template>

  <!-- Перечисление Class -->
  <xsl:template match="packagedElements" mode="class">
    <xsl:if test="not(count(//class)=0)">
      <h3>Классы</h3>
      <table>
        <tr>
          <th></th>
          <th>Класс</th>
          <th>Описание</th>
        </tr>
        <xsl:for-each select="//class">
          <xsl:sort select="@name"/>
          <tr>
            <td>
              <img alt="Класс" img="images/clear.gif" class="class"/>
            </td>
            <td>
              <a>
                <xsl:attribute name="href">
                  <xsl:text>#</xsl:text>
                  <xsl:value-of select="@Id"/>
                </xsl:attribute>
                <xsl:value-of select="@name"/>
              </a>
            </td>
            <td>
              <xsl:value-of select="description"/>
            </td>
          </tr>
        </xsl:for-each>
      </table>
    </xsl:if>
  </xsl:template>

  <!-- Перечисление  Enum -->
  <xsl:template match="packagedElements" mode="enumeration">
    <xsl:if test="not(count(//enumeration)=0)">
      <h3>Перечисления</h3>
      <table>
        <tr>
          <th></th>
          <th>Класс</th>
          <th>Описание</th>
        </tr>
        <xsl:for-each select="//enumeration">
          <xsl:sort select="@name"/>
          <tr>
            <td>
              <img alt="Перечисление" img="images/clear.gif" class="enum"/>
            </td>
            <td>
              <a>
                <xsl:attribute name="href">
                  <xsl:text>#</xsl:text>
                  <xsl:value-of select="@Id"/>
                </xsl:attribute>
                <xsl:value-of select="@name"/>
              </a>
            </td>
            <td>
              <xsl:value-of select="description"/>
            </td>
          </tr>
        </xsl:for-each>
      </table>
    </xsl:if>
  </xsl:template>

  <!-- Детализация класса -->
  <xsl:template match="class">
    <h3>
      <xsl:attribute name="id">
        <xsl:value-of select="@Id"/>
      </xsl:attribute>
      <span>Класс :: </span>
      <xsl:value-of select="@name"/>
    </h3>
    <!-- Наследование -->
    <xsl:if test="not(count(./generalsInternal)=0)">
      <h4>Расширяет свойства:</h4>
      <p>
        <a>
          <xsl:attribute name="href">
            <!--<xsl:value-of select="substring(./generalsInternal/generalization/classMoniker/@LastKnownLocation,1,string-length(./generalsInternal/generalization/classMoniker/@LastKnownLocation)-4)"/>
            <xsl:text>.xml</xsl:text>-->
            <xsl:text>#</xsl:text>
            <xsl:value-of select="./generalsInternal/generalization/classMoniker/@Id"/>
          </xsl:attribute>
          <xsl:value-of select="./generalsInternal/generalization/classMoniker/@LastKnownName"/>
        </a>
      </p>
    </xsl:if>
    <p class="desc">
      <xsl:value-of select="description"/>
    </p>
    <!-- Свойства -->
    <xsl:if test="not(count(ownedAttributesInternal/property))=0">
      <h4>Свойства</h4>
      <table>
        <tr>
          <th></th>
          <th>Название</th>
          <th>Доступ</th>
          <th>Тип</th>
          <th>Описание</th>
        </tr>
        <xsl:for-each select="ownedAttributesInternal/property">
          <tr>
            <td>
              <img alt="Свойство" img="images/clear.gif" class="property"/>
            </td>
            <td>
              <xsl:value-of select="@name"/>
            </td>
            <td>
              <xsl:choose>
                <xsl:when test="@isReadOnly='true'">
                  <xsl:text>get</xsl:text>
                </xsl:when>
                <xsl:otherwise>
                  <xsl:text>get / set</xsl:text>
                </xsl:otherwise>
              </xsl:choose>
            </td>
            <td>
              <a>
                <xsl:attribute name="href">
                  <!--<xsl:value-of select="substring(./type_NamedElement//@LastKnownLocation,1,string-length(./type_NamedElement//@LastKnownLocation)-4)"/>
                  <xsl:text>.xml</xsl:text>-->
                  <xsl:text>#</xsl:text>
                  <xsl:value-of select="./type_NamedElement//@Id"/>
                </xsl:attribute>
                <xsl:value-of select="type_NamedElement//@LastKnownName"/>
                <!-- TODO: Отображать [], если элемент массив -->
                <xsl:if test="not(count(lowerValueInternal))=0">
                  <xsl:text>[]</xsl:text>
                </xsl:if>
              </a>
            </td>
            <td>
              <xsl:value-of select="description"/>
            </td>
          </tr>
        </xsl:for-each>
      </table>
    </xsl:if>
    <!-- Методы -->
    <xsl:if test="not(count(ownedOperationsInternal/operation))=0">
      <h4>Методы</h4>
      <table>
        <tr>
          <th></th>
          <th>Название</th>
          <th>Описание</th>
        </tr>
        <xsl:for-each select="ownedOperationsInternal/operation">
          <tr>
            <td>
              <img alt="Метод" img="images/clear.gif" class="method"/>
            </td>
            <td>
              <a>
                <xsl:attribute name="href">
                  <xsl:text>#</xsl:text>
                  <xsl:value-of select="@Id"/>
                </xsl:attribute>
                <xsl:value-of select="@name"/>
              </a>
            </td>
            <td>
              <xsl:value-of select="description"/>
            </td>
          </tr>
        </xsl:for-each>
      </table>
      <xsl:for-each select="ownedOperationsInternal/operation">
        <xsl:apply-templates select="."/>
      </xsl:for-each>
    </xsl:if>

  </xsl:template>

  <!-- Детализация Метода -->
  <xsl:template match="operation">
    <h3>
      <xsl:attribute name="id">
        <xsl:value-of select="@Id"/>
      </xsl:attribute>
      <span >Метод :: </span>
      <xsl:value-of select="@name"/>
    </h3>
    <p class="desc">
      <xsl:value-of select="description"/>
    </p>
    <h4>Синтаксис</h4>
    <p class="code">
      <xsl:text>function </xsl:text>
      <xsl:value-of select="@name"/>
      <xsl:text>(</xsl:text>
      <xsl:for-each select=".//parameter[not(@direction='Return')]">
        <xsl:value-of select="@name"/>
        <!-- TODO: Отображать [], если элемент массив -->
        <xsl:if test="not(count(lowerValueInternal))=0">
          <xsl:text>[]</xsl:text>
        </xsl:if>
        <xsl:text>:</xsl:text>
        <a>
          <xsl:attribute name="href">
            <xsl:text>#</xsl:text>
            <xsl:value-of select="./type_NamedElement//@Id"/>
          </xsl:attribute>
          <xsl:value-of select=".//@LastKnownName"/>
        </a>
        <xsl:if test="not(position()=last())">
          <xsl:text>, </xsl:text>
        </xsl:if>
      </xsl:for-each>
      <xsl:text>)</xsl:text>
      <xsl:for-each select=".//parameter[@direction='Return']">
        <xsl:text>:</xsl:text>
        <a>
          <xsl:attribute name="href">
            <xsl:text>#</xsl:text>
            <xsl:value-of select="./type_NamedElement//@Id"/>
          </xsl:attribute>
          <xsl:value-of select=".//@LastKnownName"/>
        </a>
      </xsl:for-each>
    </p>
    <xsl:for-each select="ownedParameters/operationHasOwnedParameters/parameter[@direction='Return']">
      <dl class="method_params">
        <dt>
          <img alt="Переменная" img="images/clear.gif" class="param"/>
          <span class="name">Return: </span>
          <dd>
            <span>Тип: </span>
            <xsl:value-of select=".//@LastKnownName"/>
          </dd>
          <dd>
            <span>Значение: </span>
            <xsl:value-of select="description"/>
          </dd>
        </dt>
      </dl>
    </xsl:for-each>
    <xsl:if test="count(ownedParameters/operationHasOwnedParameters/parameter[not(@direction='Return')])">
      <dl class="method_params">
        <xsl:for-each select="ownedParameters/operationHasOwnedParameters/parameter[not(@direction='Return')]">
          <dt>
            <img alt="Переменная" img="images/clear.gif" class="param"/>
            <span class="name">
              <xsl:value-of select="@name"/>
            </span>
            <dd>
              <span>Тип: </span>
              <xsl:value-of select="type_NamedElement//@LastKnownName"/>
            </dd>
            <dd>
              <span>Значение: </span>
              <xsl:value-of select="description"/>
            </dd>
          </dt>
        </xsl:for-each>
      </dl>
    </xsl:if>
  </xsl:template>

  <!-- Детализация Перечисления -->
  <xsl:template match="enumeration">
    <h3>
      <xsl:attribute name="id">
        <xsl:value-of select="@Id"/>
      </xsl:attribute>
      <span>Перечисление :: </span>
      <xsl:value-of select="@name"/>
    </h3>
    <p class="desc">
      <xsl:value-of select="description"/>
    </p>
    <!-- Литералы -->
    <xsl:if test="not(count(.//enumerationLiteral))=0">
      <h4>Свойства</h4>
      <table>
        <tr>
          <th></th>
          <th>Название</th>
          <th>Описание</th>
        </tr>
        <xsl:for-each select=".//enumerationLiteral">
          <tr>
            <td>
              <img alt="Перечисление" img="images/clear.gif" class="enum"/>
            </td>
            <td>
              <xsl:value-of select="@name"/>
            </td>
            <td>
              <xsl:value-of select="description"/>
            </td>
          </tr>
        </xsl:for-each>
      </table>
    </xsl:if>
  </xsl:template>

</xsl:stylesheet>